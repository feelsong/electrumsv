import concurrent.futures
import threading
from typing import Any, Callable, cast, NamedTuple, Optional
import weakref

from PyQt5.QtCore import Qt, pyqtSignal, QUrl
from PyQt5.QtGui import QDesktopServices
from PyQt5.QtWidgets import QFrame, QGridLayout, QLabel, QHBoxLayout, QVBoxLayout, \
    QProgressDialog, QSizePolicy, QWidget

from ...app_state import app_state
from ...bitcoin import ScriptTemplate
from ...constants import AccountType, CHANGE_SUBPATH, RECEIVING_SUBPATH, ScriptType
from ...exceptions import NotEnoughFunds
from ...i18n import _
from ...logs import logs
from ...networks import Net
from ...transaction import Transaction, XTxOutput
from ...wallet import AbstractAccount

from .main_window import ElectrumWindow
from .password_dialog import LayoutFields
from .util import EnterButton, HelpDialogButton


logger = logs.get_logger("coinsplitting")

TX_DESC_PREFIX = _("ElectrumSV coin splitting")

RESULT_DUST_TIMEOUT = -2
RESULT_DIALOG_CLOSED = -1
RESULT_READY_FOR_SPLIT = 0

STAGE_INACTIVE = -1
STAGE_PREPARING = 0
STAGE_OBTAINING_DUST = 1
STAGE_SPLITTING = 2

STAGE_NAMES = {
    STAGE_INACTIVE: _("Inactive") +".",
    STAGE_PREPARING: _("Preparing") +"..",
    STAGE_OBTAINING_DUST: _("Obtaining dust") +"..",
    STAGE_SPLITTING: _("Splitting coins") +"..",
}

class AllocatedKeyState(NamedTuple):
    script_template: ScriptTemplate
    keyinstance_id: int
    script_type: ScriptType


class CoinSplittingTab(QWidget):
    _allocated_key_state: Optional[AllocatedKeyState] = None
    unfrozen_balance = None
    frozen_balance = None
    split_stage = STAGE_INACTIVE
    faucet_status_code = None

    intro_label = None
    splittable_balance_label = None
    unsplittable_balance_label = None
    splittable_unit_label = None
    unsplittable_unit_label = None
    waiting_dialog: Optional["SplitWaitingDialog"] = None

    _direct_splitting_enabled = False
    _direct_splitting = False
    _faucet_splitting_enabled = False
    _faucet_splitting = False

    def __init__(self, main_window: ElectrumWindow) -> None:
        super().__init__()

        self._main_window = cast(ElectrumWindow, weakref.proxy(main_window))
        self._main_window.account_change_signal.connect(self._on_account_change)
        self._wallet = main_window._wallet

        self._account: Optional[AbstractAccount] = None
        self._account_id: Optional[int] = None

    def _on_account_change(self, new_account_id: int, new_account: AbstractAccount) -> None:
        self._account_id = new_account_id
        self._account = new_account

        script_type = new_account.get_default_script_type()

        # Hardware wallets will not sign OP_FALSE OP_RETURN.
        self._direct_splitting_enabled = self._account.is_deterministic() and \
            new_account.can_spend() and \
            not new_account.involves_hardware_wallet()
        # The faucet requires an address to send to. There are only P2PKH addresses.
        self._faucet_splitting_enabled = self._account.is_deterministic() and \
          script_type == ScriptType.P2PKH
        self.update_layout()

    def _on_direct_split(self) -> None:
        assert self._account is not None
        assert self._direct_splitting_enabled, "direct splitting not enabled"
        assert not self._faucet_splitting, "already faucet splitting"

        self._direct_splitting = True
        self._direct_button.setText(_("Splitting") +"...")
        self._direct_button.setEnabled(False)

        unused_key = self._account.get_fresh_keys(CHANGE_SUBPATH, 1)[0]
        script_type = self._account.get_default_script_type()
        script = self._account.get_script_for_derivation(script_type, unused_key.derivation_type,
            unused_key.derivation_data2)
        coins = self._account.get_transaction_outputs_with_key_data()
        # NOTE(typing) attrs has poor typing support and does not accept correct argument order.
        outputs = [ XTxOutput(-1, script) ] # type: ignore[arg-type]
        outputs.extend(self._account.create_extra_outputs(coins, outputs, force=True))
        try:
            tx, tx_context = self._account.make_unsigned_transaction(coins, outputs)
        except NotEnoughFunds:
            self._cleanup_tx_final()
            self._main_window.show_message(_("Insufficient funds"))
            return

        if self._account.type() == AccountType.MULTISIG:
            self._cleanup_tx_final()

            tx_context.description = f"{TX_DESC_PREFIX} (multisig)"
            self._main_window.show_transaction(self._account, tx, tx_context)
            return

        amount = tx.output_value()
        fee = tx.get_fee()
        fields: LayoutFields = [
            (_("Amount to be sent"), QLabel(app_state.format_amount_and_units(amount))),
            (_("Mining fee"), QLabel(app_state.format_amount_and_units(fee))),
        ]
        msg = "\n".join([
            "",
            _("Enter your password to proceed"),
        ])
        password = self._main_window.password_dialog(msg, fields=fields)
        assert password is not None

        def sign_done(success: bool) -> None:
            if success:
                if not tx.is_complete():
                    dialog = self._main_window.show_transaction(self._account, tx, tx_context)
                    dialog.exec()
                else:
                    extra_text = _("Your split coins")
                    tx_context.description = f"{TX_DESC_PREFIX}: {extra_text}"
                    self._main_window.broadcast_transaction(self._account, tx, tx_context,
                        success_text=_("Your coins have now been split."))
            self._cleanup_tx_final()
        self._main_window.sign_tx_with_password(tx, sign_done, password, context=tx_context)

    def _on_faucet_split(self) -> None:
        assert self._account is not None
        assert self._faucet_splitting_enabled, "faucet splitting not enabled"
        assert not self._faucet_splitting, "already direct splitting"

        self._faucet_splitting = True
        self._faucet_button.setText(_("Splitting") +"...")
        self._faucet_button.setEnabled(False)

        # At this point we know we should get a key that is addressable.
        pr_future, key_data = self._account.create_payment_request(
            _("Receive faucet dust for coin-splitting."), expiration_seconds=5*60)
        script_type = self._account.get_default_script_type()
        script_template = self._account.get_script_template_for_derivation(script_type,
            key_data.derivation_type, key_data.derivation_data2)
        self._allocated_key_state = AllocatedKeyState(script_template, key_data.keyinstance_id,
            script_type)

        self.split_stage = STAGE_PREPARING
        self.new_transaction_cv = threading.Condition()

        self._main_window._wallet.register_callback(self._on_wallet_event, ['transaction_added'])
        self.waiting_dialog = SplitWaitingDialog(self._main_window.reference(), self,
            self._split_prepare_task, on_done=self._on_split_prepare_done,
            on_cancel=self._on_split_abort)

    def _split_prepare_task(self, our_dialog: 'SplitWaitingDialog') -> int:
        assert self.waiting_dialog is not None
        assert self._allocated_key_state is not None
        self.split_stage = STAGE_OBTAINING_DUST

        address_text = self._allocated_key_state.script_template.to_string()
        QDesktopServices.openUrl(QUrl("{}/?addr={}".format(Net.FAUCET_URL, address_text)))

        # Wait for the transaction to arrive.  How long it takes before the progress bar
        # stalls (should easily cover normal expected time required).
        max_time_passed_for_progress = 40.0
        # How long to wait before failing the process.
        max_time_passed_for_failure = 120.0
        was_received = False
        with self.new_transaction_cv:
            time_passed = 0.0
            while not was_received:
                if our_dialog != self.waiting_dialog:
                    return RESULT_DIALOG_CLOSED
                if time_passed >= max_time_passed_for_failure:
                    return RESULT_DUST_TIMEOUT
                self.waiting_dialog.set_stage_progress(time_passed/max_time_passed_for_progress)
                was_received = self.new_transaction_cv.wait(0.1)
                time_passed += 0.1

        # The user needs to sign the transaction.  It can't be done in this thread.
        self.split_stage = STAGE_SPLITTING
        return RESULT_READY_FOR_SPLIT

    def _on_split_abort(self) -> None:
        self._main_window.show_error(_("Coin-splitting process has been cancelled."))
        self._cleanup_tx_final()
        self._cleanup_tx_created()

    def _on_split_prepare_done(self, future: concurrent.futures.Future[int]) -> None:
        try:
            result = future.result()
        except Exception as exc:
            self._main_window.on_exception(exc)
        else:
            if result == RESULT_READY_FOR_SPLIT:
                self._ask_send_split_transaction()
                return

            if result == RESULT_DIALOG_CLOSED:
                self._main_window.show_error(_("Coin-splitting process has been cancelled."))
            elif result == RESULT_DUST_TIMEOUT:
                self._main_window.show_error(_("It took too long to get the dust from the faucet."))
            else:
                self._main_window.show_error(_("Unexpected situation. You should not even be "
                                               "here."))
            self._cleanup_tx_final()
        finally:
            self._cleanup_tx_created()

    def _ask_send_split_transaction(self) -> None:
        assert self._account is not None
        assert self._allocated_key_state is not None

        coins = self._account.get_transaction_outputs_with_key_data()
        # Verify that our dust receiving address is in the available UTXOs, if it isn't, the
        # process has failed in some unexpected way.
        for coin in coins:
            if (coin.keyinstance_id == self._allocated_key_state.keyinstance_id and
                    coin.script_type == self._allocated_key_state.script_type):
                break
        else:
            self._main_window.show_error(_("Error accessing dust coins for correct splitting."))
            self._cleanup_tx_final()
            return

        unused_key = self._account.get_fresh_keys(RECEIVING_SUBPATH, 1)[0]
        script_type = self._account.get_default_script_type()
        script = self._account.get_script_for_derivation(script_type,
            unused_key.derivation_type, unused_key.derivation_data2)
        # NOTE(typing) attrs has issues with typing. It cannot work out how the arguments work.
        outputs = [ XTxOutput(-1, script) ] # type: ignore[arg-type]
        tx, tx_context = self._account.make_unsigned_transaction(coins, outputs)
        tx_context.description = f"{TX_DESC_PREFIX}: {_('Your split coins')}"

        amount = tx.output_value()
        fee = tx.get_fee()

        msg = [
            _("Amount to be sent") + ": " + app_state.format_amount_and_units(amount),
            _("Mining fee") + ": " + app_state.format_amount_and_units(fee),
        ]

        msg.append("")
        msg.append(_("Enter your password to proceed"))
        password = self._main_window.password_dialog('\n'.join(msg))
        if password is None:
            self._cleanup_tx_final()
            return

        def sign_done(success: bool) -> None:
            if success:
                if not tx.is_complete():
                    dialog = self._main_window.show_transaction(self._account, tx)
                    dialog.exec()
                else:
                    self._main_window.broadcast_transaction(self._account, tx,
                        success_text=_("Your coins have now been split."))
            self._cleanup_tx_final()
        self._main_window.sign_tx_with_password(tx, sign_done, password, context=tx_context)

    def _cleanup_tx_created(self) -> None:
        self._main_window._wallet.unregister_callback(self._on_wallet_event)

        self._allocated_key_state = None
        self.waiting_dialog = None
        self.faucet_status_code = None
        self.split_stage = STAGE_INACTIVE

    def _cleanup_tx_final(self) -> None:
        logger.debug("final cleanup performed")
        if self._direct_splitting:
            self._direct_button.setText(_("Direct Split"))
            self._direct_button.setEnabled(True)
            self._direct_splitting = False
        if self._faucet_splitting:
            self._faucet_button.setText(_("Faucet Split"))
            self._faucet_button.setEnabled(True)
            self._faucet_splitting = False

    def _on_wallet_event(self, event: str, *args: Any) -> None:
        if event == 'transaction_added':
            if self._allocated_key_state is None:
                return

            if self._account_id not in args[2].account_ids:
                return
            assert self._account is not None

            our_script = self._allocated_key_state.script_template.to_script_bytes()
            # args = (tx_hash, tx, involved_account_ids, import_flags)
            tx: Transaction = args[1]
            for tx_output in tx.outputs:
                if tx_output.script_pubkey == our_script:
                    extra_text = _("Dust from BSV faucet")
                    self._account.set_transaction_label(tx.hash(),
                        f"{TX_DESC_PREFIX}: {extra_text}")
                    # Notify the progress dialog task thread.
                    with self.new_transaction_cv:
                        self.new_transaction_cv.notify()
                    break

    def update_layout(self) -> None:
        if self._account is None:
            vbox = self._create_disabled_layout(_("No active account."))
            self._replace_layout(vbox)
            return

        intro_text = _("If this account contains coins that may be linked on both the Bitcoin SV "
            "blockchain and the Bitcoin Cash blockchain, then the approaches listed below "
            "can be used to unlink (also known as coin-splitting) them. If no approaches are "
            "enabled or you want to take control of the process, refer to the help offered "
            "below.")

        direct_text = _("The recommended approach. This approach "
            "will combine the coins in this account into a Bitcoin SV only transaction and send "
            "them back to this account.")
        if not self._direct_splitting_enabled:
            direct_text += "<br/><br/>"
            direct_text += "<i>"+ _("Incompatible with this account type.") +"</i>"

        faucet_text = _("The fallback approach. This approach requests a very small amount "
            "of known Bitcoin SV coins and combines it with the coins in this account and sends "
            "them back to this account.")
        if not self._faucet_splitting_enabled:
            faucet_text += "<br/><br/>"
            faucet_text += "<i>"+ _("Incompatible with this account type.") +"</i>"

        self._intro_label = QLabel()
        self._intro_label.setWordWrap(True)
        self._intro_label.setMaximumWidth(600)
        self._intro_label.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.MinimumExpanding)
        self._intro_label.setText(intro_text)
        self._intro_label.setMinimumHeight(self._intro_label.sizeHint().height() + 8)

        self._direct_label = QLabel(direct_text)
        self._direct_label.setMaximumWidth(300)
        self._direct_label.setMinimumWidth(300)
        self._direct_label.setWordWrap(True)

        self._faucet_label = QLabel(faucet_text)
        self._faucet_label.setMaximumWidth(300)
        self._faucet_label.setMinimumWidth(300)
        self._faucet_label.setWordWrap(True)

        self._faucet_button = EnterButton(_("Faucet Split"), self._on_faucet_split)
        self._faucet_button.setEnabled(self._faucet_splitting_enabled)

        self._direct_button = EnterButton(_("Direct Split"), self._on_direct_split)
        self._direct_button.setEnabled(self._direct_splitting_enabled)

        vbox = QVBoxLayout()
        vbox.addStretch(1)
        vbox.addWidget(self._intro_label, 0, Qt.AlignmentFlag.AlignCenter)
        vbox.addStretch(1)

        grid = QGridLayout()
        grid.setColumnStretch(0, 1)
        grid.setColumnMinimumWidth(1, 100)
        grid.setColumnStretch(3, 1)
        row_index = 0

        line = QFrame()
        line.setStyleSheet("QFrame { border: 1px solid #E3E2E2; }")
        line.setFrameShape(QFrame.HLine)
        line.setFixedHeight(1)

        grid.addWidget(line, row_index, 1, 1, 2)
        row_index += 1

        grid.addWidget(self._direct_button, row_index, 1, 1, 1, Qt.AlignmentFlag.AlignLeft)
        grid.addWidget(self._direct_label, row_index, 2, 1, 1, Qt.AlignmentFlag.AlignCenter)
        row_index += 1

        line = QFrame()
        line.setStyleSheet("QFrame { border: 1px solid #E3E2E2; }")
        line.setFrameShape(QFrame.HLine)
        line.setFixedHeight(1)

        grid.addWidget(line, row_index, 1, 1, 2)
        row_index += 1

        grid.addWidget(self._faucet_button, row_index, 1, 1, 1, Qt.AlignmentFlag.AlignLeft)
        grid.addWidget(self._faucet_label, row_index, 2, 1, 1, Qt.AlignmentFlag.AlignCenter)
        row_index += 1

        line = QFrame()
        line.setStyleSheet("QFrame { border: 1px solid #E3E2E2; }")
        line.setFrameShape(QFrame.HLine)
        line.setFixedHeight(1)

        grid.addWidget(line, row_index, 1, 1, 2)
        row_index += 1

        self._help_button = HelpDialogButton(self, "misc", "coinsplitting-tab", _("Help"))

        vbox.addLayout(grid)
        vbox.addStretch(1)
        vbox.addWidget(self._help_button, 0, Qt.AlignmentFlag.AlignCenter)
        vbox.addStretch(1)

        self._replace_layout(vbox)

    def _create_disabled_layout(self, disabled_text: str) -> QVBoxLayout:
        label = QLabel(disabled_text)

        hbox = QHBoxLayout()
        hbox.addWidget(label, 0,
            Qt.AlignmentFlag(Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter))

        vbox = QVBoxLayout()
        vbox.addLayout(hbox)

        return vbox

    def _replace_layout(self, layout: QVBoxLayout) -> None:
        # If the tab is already laid out, it's current layout needs to be
        # reparented/removed before we can replace it.
        existingLayout = self.layout()
        if existingLayout:
            QWidget().setLayout(existingLayout)
        self.setLayout(layout)


class SplitWaitingDialog(QProgressDialog):
    update_signal = pyqtSignal()
    update_label = None
    was_rejected = False

    def __init__(self, parent: QWidget, splitter: CoinSplittingTab, func: Callable[..., int],
            on_done: Callable[[concurrent.futures.Future[int]], None],
            on_cancel: Callable[[], None]) -> None:
        self.splitter = splitter

        # These flags remove the close button, which removes a corner case that we'd
        # otherwise have to handle.
        super().__init__("", "", 0, 100, parent,
            Qt.WindowType(Qt.WindowType.Window | Qt.WindowType.WindowTitleHint))
        # | Qt.WindowFlags.CustomizeWindowHint)

        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setWindowTitle(_("Please wait"))

        self.stage_progress = 0.

        def _on_done(future: concurrent.futures.Future[int]) -> None:
            if self.was_rejected:
                return
            self.accept()
            on_done(future)
        future = app_state.app_qt.run_in_thread(func, self, on_done=_on_done)
        self.accepted.connect(future.cancel)
        def _on_rejected() -> None:
            self.was_rejected = True
            future.cancel()
            on_cancel()
        self.rejected.connect(_on_rejected)
        self.update_signal.connect(self._update)
        self._update()
        self.show()

    def set_stage_progress(self, stage_progress: float) -> None:
        self.stage_progress = max(0, min(0.99, stage_progress))
        self.update_signal.emit()

    def _update(self) -> None:
        self.setValue(max(1, int(self.stage_progress * 100)))
        update_text = STAGE_NAMES[self.splitter.split_stage]
        if self.update_label is None:
            self.update_label = QLabel(update_text)
            self.setLabel(self.update_label)
        else:
            self.update_label.setText(update_text)
