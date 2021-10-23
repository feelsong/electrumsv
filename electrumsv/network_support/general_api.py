# Open BSV License version 3
# Copyright (c) 2021 Bitcoin Association
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# 1 - The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 2 - The Software, and any software that is derived from the Software or parts thereof,
# can only be used on the Bitcoin SV blockchains. The Bitcoin SV blockchains are defined,
# for purposes of this license, as the Bitcoin blockchain containing block height #556767
# with the hash "000000000000000001d956714215d96ffc00e0afda4cd0a96c96f8d802b1662b" and
# that contains the longest persistent chain of blocks that are accepted by the un-modified
# Software, as well as the test blockchains that contain blocks that are accepted by the
# un-modified Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

import json
from typing import Generator, List, Optional, TypedDict, TypeVar # , TYPE_CHECKING

import certifi
import requests


T = TypeVar("T")


# Used for requests.
ca_path = certifi.where()


class RestorationFilterRequest(TypedDict):
    filterKeys: List[str]

class RestorationFilterResponse(TypedDict):
    pushDataHashHex: str
    transactionId: str
    index: int
    referenceType: int
    spendTransactionId: Optional[str]
    spendInputIndex: int


class GeneralAPIError(Exception):
    pass

class FilterResponseInvalidError(GeneralAPIError):
    pass

class FilterResponseIncompleteError(GeneralAPIError):
    pass


def post_restoration_filter_request_json(url: str, request_data: RestorationFilterRequest) \
        -> Generator[RestorationFilterResponse, None, None]:
    """
    This will stream matches for the given push data hashes from the server in JSON
    structures until there are no more matches.

    Raises `HTTPError` if the response status code indicates an error occurred.
    Raises `FilterResponseInvalidError` if the response content type does not match what we accept.
    """
    with requests.post(url,
            json=request_data,
            headers={
                'Content-Type':     'application/json',
                'Accept':           'application/json',
                'User-Agent':       'ElectrumSV'
            },
            verify=ca_path,
            stream=True) as response:
        response.raise_for_status()

        content_type, *content_type_extra = response.headers["Content-Type"].split(";")
        if content_type != "application/json":
            raise FilterResponseInvalidError(
                "Invalid response content type, got {}, expected {}".format(content_type,
                    "application/json"))

        for response_line in response.iter_lines():
            yield json.loads(response_line)


FILTER_RESPONSE_SIZE = 32 + 32 + 32 + 4 + 4 + 1


def post_restoration_filter_request_binary(url: str, request_data: RestorationFilterRequest) \
        -> Generator[bytes, None, None]:
    """
    This will stream matches for the given push data hashes from the server in packed binary
    structures until there are no more matches.

    Raises `HTTPError` if the response status code indicates an error occurred.
    Raises `FilterResponseInvalidError` if the response content type does not match what we accept.
    Raises `FilterResponseIncompleteError` if a response packet is incomplete. This likely means
      that the connection was closed mid-transmission.
    """
    with requests.post(url,
            json=request_data,
            headers={
                'Content-Type':     'application/json',
                'Accept':           'application/octet-stream',
                'User-Agent':       'ElectrumSV'
            },
            verify=ca_path,
            stream=True) as response:
        response.raise_for_status()

        content_type, *content_type_extra = response.headers["Content-Type"].split(";")
        if content_type != "application/octet-stream":
            raise FilterResponseInvalidError(
                "Invalid response content type, got {}, expected {}".format(content_type,
                    "octet-stream"))

        packet_bytes: bytes
        for packet_bytes in response.iter_content(chunk_size=FILTER_RESPONSE_SIZE):
            if len(packet_bytes) != FILTER_RESPONSE_SIZE:
                raise FilterResponseIncompleteError("...")

            yield packet_bytes

