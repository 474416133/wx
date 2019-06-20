#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "sven"

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
    return "<xml>{}</xml>".format("\n".join(["<{}><![CDATA[{}]]></{}>".format(key, data[key], key) for key in data]))


def uuid32():
    """
    返回uuid 32
    :return:
    """
    return ''.join(uuid.uuid4().hex.split("-"))

def generate_sign_MD5(mustbe_dict):
    """
    生成签名
    :param mustbe_dict:
    :return:
    """
    sign_str = "&".join(["{}={}".format(key, mustbe_dict[key]) for key in sorted(mustbe_dict.keys())])
    return hashlib.md5(sign_str).hexdigest().upper()


def generate_xml(mustbe_dict, mch_key, sign_generator=generate_sign_MD5, dict2xml=dict_to_xml):
    """
    生成xml
    :param mustbe_dict:
    :param mch_key:
    :param dict2xml:
    :return:
    """
    mustbe_dict["key"] = mch_key
    sign = sign_generator(mustbe_dict)
    mustbe_dict["sign"] = sign
    mustbe_dict.pop("key", None)
    return dict_to_xml(mustbe_dict)




