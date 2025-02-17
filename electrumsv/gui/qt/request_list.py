#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from enum import IntEnum
from functools import partial
import math
import time
from typing import Optional, TYPE_CHECKING
import weakref

from PyQt5.QtCore import pyqtSignal, QPoint, Qt, QTimer
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QLabel, QTreeWidgetItem, QMenu, QVBoxLayout

from ...app_state import app_state
from ...bitcoin import script_template_to_string
from ...constants import PaymentFlag
from ...i18n import _
from ...logs import logs
from ...paymentrequest import PaymentRequest
from ...platform import platform
from ...util import format_posix_timestamp, get_posix_timestamp
from ...wallet import AbstractAccount
from ...web import create_URI

from .constants import pr_icons, pr_tooltips
from .qrtextedit import ShowQRTextEdit
from .util import Buttons, CopyCloseButton, MessageBox, MyTreeWidget, read_QIcon, WindowModalDialog

if TYPE_CHECKING:
    from .main_window import ElectrumWindow
    from .receive_view import ReceiveView



class RequestColumn(IntEnum):
    DATE = 0
    DESCRIPTION = 1
    AMOUNT_REQUESTED = 2
    AMOUNT_RECEIVED = 3
    STATUS = 4


# TODO(ScriptTypeAssumption) It is assumed that all active payment requests from the receive tab
# are given out for the wallet's default script type. This isn't necessarily true but is close
# enough for now. To fix it we'd have to extend the database table, and also display the
# script type in the list or similarly allow the user to see it.

class RequestList(MyTreeWidget):
    filter_columns = [
        RequestColumn.DATE,
        RequestColumn.DESCRIPTION,
        RequestColumn.AMOUNT_REQUESTED,
        RequestColumn.AMOUNT_RECEIVED,
        RequestColumn.STATUS,
    ]

    update_signal = pyqtSignal()

    def __init__(self, receive_view: 'ReceiveView', main_window: 'ElectrumWindow') -> None:
        self._receive_view = receive_view
        self._main_window = weakref.proxy(main_window)
        self._account: Optional[AbstractAccount] = main_window._account
        self._account_id: Optional[int] = main_window._account_id

        self._monospace_font = QFont(platform.monospace_font)
        self._logger = logs.get_logger("request-list")

        MyTreeWidget.__init__(self, receive_view, main_window, self.create_menu, [
            _('Date'), _('Description'), _('Requested Amount'), _('Received Amount'), _('Status')],
            stretch_column=RequestColumn.DESCRIPTION,
            editable_columns=[])

        self.itemDoubleClicked.connect(self._on_item_double_clicked)
        self.setSortingEnabled(True)
        self.setColumnWidth(RequestColumn.DATE, 180)

        self.update_signal.connect(self.update)

        # This is used if there is a pending expiry.
        self._timer: Optional[QTimer] = None
        self._timer_event_time = 0.

    def _start_timer(self, event_time: float) -> None:
        self._stop_timer()

        self._timer_event_time = event_time
        all_seconds = math.ceil(event_time - time.time())
        # Cap the time spent waiting to 50 seconds
        seconds = min(all_seconds, 50) # * 60)
        assert seconds > 0, f"got invalid timer duration {seconds}"
        # self._logger.debug("start_timer for %d seconds", seconds)
        interval = seconds * 1000

        assert self._timer is None, "timer already active"
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._on_timer_event)
        self._timer.start(interval)

    def _stop_timer(self) -> None:
        if self._timer is None:
            return
        self._timer.stop()
        self._timer = None
        self._timer_event_time = 0.

    def _on_timer_event(self) -> None:
        """
        This should be triggered when the nearest expiry time is reached.

        The updating of the list should if necessary restart a timer for the new nearest expiry
        time, if there is one.
        """
        event_time = self._timer_event_time
        self._stop_timer()
        if event_time == 0:
            return

        if event_time > time.time():
            self._start_timer(event_time)
        else:
            self.update()

    def _on_item_double_clicked(self, item: QTreeWidgetItem) -> None:
        if item is None:
            return
        if not item.isSelected():
            return
        request_id = item.data(0, Qt.ItemDataRole.UserRole)
        self._receive_view.show_dialog(request_id)

    def on_update(self) -> None:
        # This is currently triggered by events like 'transaction_added' from the main window.
        if self._account_id is None:
            return
        assert self._account is not None

        current_time = get_posix_timestamp()
        nearest_expiry_time = float('inf')

        wallet = self._account._wallet
        rows = wallet.read_payment_requests(self._account_id, flags=PaymentFlag.NONE,
            mask=PaymentFlag.ARCHIVED)

        # clear the list and fill it again
        self.clear()
        for row in rows:
            flags = row.state & PaymentFlag.MASK_STATE
            date = format_posix_timestamp(row.date_created, _("Unknown"))
            requested_amount_str = app_state.format_amount(row.requested_value, whitespaces=True) \
                if row.requested_value else ""
            received_amount_str = app_state.format_amount(row.received_value, whitespaces=True) \
                if row.received_value else ""

            if flags == PaymentFlag.UNPAID and row.expiration is not None:
                date_expires = row.date_created + row.expiration
                if date_expires < current_time + 5:
                    flags = (flags & ~PaymentFlag.UNPAID) | PaymentFlag.EXPIRED
                else:
                    nearest_expiry_time = min(nearest_expiry_time, date_expires)

            state = flags & sum(pr_icons.keys())
            item = QTreeWidgetItem([
                date,
                row.description or "",
                requested_amount_str,
                received_amount_str,
                pr_tooltips.get(state,'')
            ])
            item.setData(RequestColumn.DATE, Qt.ItemDataRole.UserRole, row.paymentrequest_id)
            if state != PaymentFlag.UNKNOWN:
                icon_name = pr_icons.get(state)
                if icon_name is not None:
                    item.setIcon(RequestColumn.STATUS, read_QIcon(icon_name))
            item.setFont(RequestColumn.AMOUNT_REQUESTED, self._monospace_font)
            item.setFont(RequestColumn.AMOUNT_RECEIVED, self._monospace_font)
            self.addTopLevelItem(item)

        if nearest_expiry_time != float("inf"):
            self._start_timer(nearest_expiry_time)

    def create_menu(self, position: QPoint) -> None:
        item = self.itemAt(position)
        if not item:
            return
        request_id = item.data(RequestColumn.DATE, Qt.ItemDataRole.UserRole)
        column = self.currentColumn()
        column_title = self.headerItem().text(column)
        column_data = item.text(column).strip()
        menu = QMenu(self)
        menu.addAction(_("Details"), lambda: self._receive_view.show_dialog(request_id))
        menu.addAction(_("Copy {}").format(column_title),
            lambda: app_state.app_qt.clipboard().setText(column_data))
        menu.addAction(_("Copy URI"),
            lambda: self._view_and_paste('URI', '', self._get_request_URI(request_id)))
        action = menu.addAction(_("Save as BIP270 file"),
            lambda: self._export_payment_request(request_id))
        # There cannot be a payment URI at this time.
        # TODO: Revisit when there is a identity and hosted service.
        action.setEnabled(False)
        menu.addAction(_("Delete"), partial(self._delete_payment_request, request_id))
        menu.exec_(self.viewport().mapToGlobal(position))

    def _get_request_URI(self, pr_id: int) -> str:
        assert self._account is not None
        wallet = self._account.get_wallet()
        req = self._account._wallet.read_payment_request(request_id=pr_id)
        assert req is not None
        message = self._account.get_keyinstance_label(req.keyinstance_id)
        # TODO(ScriptTypeAssumption) see above for context
        keyinstance = wallet.read_keyinstance(keyinstance_id=req.keyinstance_id)
        assert keyinstance is not None
        script_template = self._account.get_script_template_for_derivation(
            self._account.get_default_script_type(),
            keyinstance.derivation_type, keyinstance.derivation_data2)
        address_text = script_template_to_string(script_template)

        URI = create_URI(address_text, req.requested_value, message)
        URI += f"&time={req.date_created}"
        if req.expiration:
            URI += f"&exp={req.expiration}"
        return str(URI)

    def _export_payment_request(self, pr_id: int) -> None:
        assert self._account is not None
        pr = self._account._wallet.read_payment_request(request_id=pr_id)
        assert pr is not None
        pr_data = PaymentRequest.from_wallet_entry(self._account, pr).to_json()
        name = f'{pr.paymentrequest_id}.bip270.json'
        fileName = self._main_window.getSaveFileName(
            _("Select where to save your payment request"), name, "*.bip270.json")
        if fileName:
            with open(fileName, "w") as f:
                f.write(pr_data)
            self.show_message(_("Request saved successfully"))

    def _delete_payment_request(self, request_id: int) -> None:
        assert self._account_id is not None and self._account is not None

        # Blocking deletion call.
        wallet = self._account.get_wallet()
        row = wallet.read_payment_request(request_id=request_id)
        if row is None:
            return

        if not MessageBox.question(_("Are you sure you want to delete this payment request?")):
            return

        future = wallet.delete_payment_request(self._account_id, request_id, row.keyinstance_id)
        future.result()

        self.update_signal.emit()
        self._receive_view.update_contents()

    def _view_and_paste(self, title: str, msg: str, data: str) -> None:
        dialog = WindowModalDialog(self, title)
        vbox = QVBoxLayout()
        label = QLabel(msg)
        label.setWordWrap(True)
        vbox.addWidget(label)
        pr_e = ShowQRTextEdit(text=data)
        vbox.addWidget(pr_e)
        vbox.addLayout(Buttons(CopyCloseButton(pr_e.text, app_state.app_qt, dialog)))
        dialog.setLayout(vbox)
        dialog.exec_()
