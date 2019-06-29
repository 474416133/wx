#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "sven"

import sys
sys.path.insert(0, "../wx_pay")

import pytest
from wx_pay.utils import (xml_to_dict, dict_to_xml)
from wx_pay import AsyncClient

import logging
logging.basicConfig(level=logging.DEBUG)

@pytest.fixture()
def xml_doc():
    """ sample as follow:
        <xml><appid><![CDATA[]]></appid>
    <bank_type><![CDATA[COMM_CREDIT]]></bank_type>
    <cash_fee><![CDATA[55800]]></cash_fee>
    <fee_type><![CDATA[CNY]]></fee_type>
    <is_subscribe><![CDATA[N]]></is_subscribe>
    <mch_id><![CDATA[1xxxxxxxx]]></mch_id>
    <nonce_str><![CDATA[48287d7xxxxx]]></nonce_str>
    <openid><![CDATA[xxxxxxxxx]]></openid>
    <out_trade_no><![CDATA[2017xxxxxx]]></out_trade_no>
    <result_code><![CDATA[SUCCESS]]></result_code>
    <return_code><![CDATA[SUCCESS]]></return_code>
    <sign><![CDATA[593409951DA5A621FB494DA0FE71F347]]></sign>
    <time_end><![CDATA[2017xxxxxxxx]]></time_end>
    <total_fee>55800</total_fee>
    <trade_type><![CDATA[JSAPI]]></trade_type>
    <transaction_id><![CDATA[420000xxxxxxxxx]]></transaction_id>
    </xml>
    """
    return """<xml><appid><![CDATA[]]></appid>
    <bank_type><![CDATA[COMM_CREDIT]]></bank_type>
    <cash_fee><![CDATA[55800]]></cash_fee>
    <fee_type><![CDATA[CNY]]></fee_type>
    <is_subscribe><![CDATA[N]]></is_subscribe>
    <mch_id><![CDATA[1xxxxxxxx]]></mch_id>
    <nonce_str><![CDATA[48287d7xxxxx]]></nonce_str>
    <openid><![CDATA[xxxxxxxxx]]></openid>
    <out_trade_no><![CDATA[2017xxxxxx]]></out_trade_no>
    <result_code><![CDATA[SUCCESS]]></result_code>
    <return_code><![CDATA[SUCCESS]]></return_code>
    <sign><![CDATA[593409951DA5A621FB494DA0FE71F347]]></sign>
    <time_end><![CDATA[2017xxxxxxxx]]></time_end>
    <total_fee>55800</total_fee>
    <trade_type><![CDATA[JSAPI]]></trade_type>
    <transaction_id><![CDATA[420000xxxxxxxxx]]></transaction_id>
    </xml>"""

def test_xml2dict(xml_doc):
    """

    :param xml_doc:
    :return:
    """
    _data = xml_to_dict(xml_doc)
    logging.debug("data:%s"%_data)
    assert _data["id"] == 123

def test_dict2xml(xml_doc):
    """

    :param xml_doc:
    :return:
    """
    _data = xml_to_dict(xml_doc)
    _xml = dict_to_xml(_data)
    logging.debug("xml: {}".format(_xml))
    assert _xml == xml_doc

def test_validate_sign(xml_doc):
    """
    校验签名
    :param xml_doc:
    :return:
    """
    client = AsyncClient(mch_id="", mch_key="",
                         appid="", app_secret=None)
    assert client._sign_genertor != None
    is_pass, _json = client.parse_xml(xml_doc)
    assert  is_pass == True