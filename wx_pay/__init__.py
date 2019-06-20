#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "sven"

import aiohttp

from wx_pay.utils import (uuid32,
                          dict_to_xml,
                          xml_to_dict,
                          generate_sign_MD5)


class AsyncClient(object):
    """
    支付
    """
    SIGN_KEY = "key"
    def __init__(self, mch_id, mch_key, appid, app_secret, ip=None, notify_url=None,
                 nonce_str_func= uuid32, dict2xml=dict_to_xml, xml2dict=xml_to_dict,
                 sign_genertor=generate_sign_MD5, json_dumps=None, json_loads=None):
        """

        """
        self._mch_id = mch_id
        self._mch_key = mch_key
        self._appid = appid
        self._app_secret = app_secret
        self._ip = ip
        self._notify_url = notify_url
        self._nonce_str_func = nonce_str_func
        self._xml2dict = xml2dict
        self._dict2xml = dict2xml
        self._sign_genertor = sign_genertor
        self._json_dumps = json_dumps
        self._json_loads = json_loads

    async def _execute(self, url, method="GET", params=None, data=None, headers=None, ssl=None):
        """
        http请求
        :param url:
        :param data:
        :param method:
        :param schema:
        :param ssl:
        :return:
        """
        async with aiohttp.ClientSession() as session:
            async with session.request(method=method.lower(), url=url, params=params, data=data, headers=headers, ssl=ssl) as resp:
                #await resp.text()
                return resp

    async def execute(self, url, method="GET", params=None, data=None, headers=None, ssl=None, resp_body_handler=None):
        """
        http请求，并返回经resp_body_handler处理过的结果
        :param url:
        :param method:
        :param params:
        :param data:
        :param headers:
        :param ssl:
        :param resp_body_handler:
        :return:
        """
        resp = await self._execute(url, method=method, params=params, data=data, headers=headers, ssl=ssl)
        if not callable(resp_body_handler):
            return resp
        _body = await resp.text()
        return resp_body_handler(_body)


    def validate_sign(self, mustbe_dict):
        """
        校验签名
        :param mustbe_dict:
        :return:
        """
        sign = mustbe_dict.pop("sign", None)
        if not sign:
            return False
        mustbe_dict[self.SIGN_KEY] = self._mch_key
        return sign == self._sign_generator(mustbe_dict)

    def parse_xml(self, xml_doc):
        """
        解析xml， 并返回dict
        :param xml_doc:
        :return:
        """
        _dict = self._xml2dict(xml_doc)
        sign = _dict.pop("sign", None)
        if self.validate_sign(_dict):
            _dict.pop(self.SIGN_KEY, None)
            return True, _dict
        return False, None

    def generate_xml(self, mustbe_dict):
        """
        生成xml
        :param mustbe_dict:
        :return:
        """
        mustbe_dict[self.SIGN_KEY] = self._mch_key
        sign = self._sign_generator(mustbe_dict)
        mustbe_dict["sign"] = sign
        mustbe_dict.pop(self.SIGN_KEY, None)
        return self._dict2xml(mustbe_dict)

    async def unified_order(self, product_dict, openid, trade_type="JSAPI"):
        """
        统一下单
        :param product_dict:
        :param openid:
        :param trade_type:
        :return:
        """
        if not isinstance(product_dict, dict):
            raise RuntimeError("arg product_dict must be a dict")
        if trade_type not in ("JSAPI", "NATIVE"):
            raise RuntimeError("trade_type either JSAPI or NATIVE")
        if trade_type == "JSAPI" and not openid:
            raise RuntimeError("openid must be presented when trade_type=JSAPI")

        product_dict.update(appid=self._appid,
                            mch_id=self._mch_id,
                            nonce_str=self._nonce_str_func,
                            notify_url=self._notify_url,
                            spbill_create_ip=self._ip,
                            trade_type=trade_type)

        _body = self.generate_xml(product_dict)
        return  await self.execute('https://api.mch.weixin.qq.com/pay/unifiedorder',
                                            method="post",
                                            data=_body,
                                            resp_body_handler=self.parse_xml)



