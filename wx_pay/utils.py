#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "sven"
import logging

import uuid
import hashlib
import xml.etree.cElementTree as ET


def xml_to_dict(xml_doc):
    """
    xml转dict
    :param xml_doc:
    :return:
    """
    pairs = []
    for element in ET.fromstring(xml_doc).iter():
        pairs.append((element.tag, element.text))
    return dict(pairs[1:])

def dict_to_xml(data):
    """
    dict转xml
    :param data:
    :return:
    """
    return "<xml>{0}</xml>".format("\n".join(["<{0}><![CDATA[{1}]]></{0}>".format(key, data[key]) for key in data if data[key] is not None]))


def uuid32():
    """
    返回uuid 32
    :return:
    """
    return ''.join(uuid.uuid4().hex.split("-"))

def generate_sign_MD5(mustbe_dict, key):
    """
    生成签名
    :param mustbe_dict:
    :return:
    """
    sign_str = "&".join(["{}={}".format(key, mustbe_dict[key]) for key in sorted(mustbe_dict.keys()) if mustbe_dict[key] is not None])
    sign_str += "&key=%s"%key
    return hashlib.md5(sign_str.encode("utf-8")).hexdigest().upper()






