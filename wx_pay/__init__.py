#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "sven"

import logging
import ssl
import aiohttp

from wx_pay.utils import (uuid32,
                          dict_to_xml,
                          xml_to_dict,
                          generate_sign_MD5)

logger = logging.getLogger("wx_pay")

class AsyncClient(object):
    """
    支付
    """
    SIGN_KEY = "key"
    CODE_SUCCESS = "SUCCESS"

    def __init__(self, mch_id, mch_key, appid, app_secret, ip=None, notify_url=None,
                 nonce_str_func= uuid32, dict2xml=dict_to_xml, xml2dict=xml_to_dict,
                 sign_genertor=generate_sign_MD5, json_dumps=None, json_loads=None,
                 cert_path=None, key_path=None):
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
        self._ssl_context = None
        if cert_path and key_path:
            self._ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self._ssl_context.load_cert_chain(cert_path, key_path)

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
        :param mustbe_dict: 必须是字典
        :return:
        """
        sign = mustbe_dict.pop("sign", None)
        if not sign:
            return False
        _sign = self._sign_genertor(mustbe_dict, self._mch_key)
        logger.debug("sign0: {}, sign1: {}".format(sign, _sign))
        return _sign == sign

    def parse_xml(self, xml_doc):
        """
        解析xml， 并返回dict
        :param xml_doc: xml文本
        :return:
        """
        _dict = self._xml2dict(xml_doc)
        if self.validate_sign(_dict):
            return True, _dict
        return False, None

    def generate_xml(self, mustbe_dict):
        """
        根据dict生成xml
        :param mustbe_dict:
        :return:
        """
        sign = self._sign_genertor(mustbe_dict, self._mch_key)
        mustbe_dict["sign"] = sign
        return self._dict2xml(mustbe_dict)

    async def unified_order(self, product_dict, openid=None, trade_type="JSAPI"):
        """
        统一下单
        :param product_dict:
        详细规则参考 https://pay.weixin.qq.com/wiki/doc/api/jsapi.php?chapter=9_1
        :type product_dict : dict
        :key body: 商品描述
        :key total_fee: 总金额，单位分
        :key client_ip: 可选，APP和网页支付提交用户端ip，Native支付填调用微信支付API的机器IP
        :key user_id: 可选，用户在商户appid下的唯一标识。trade_type=JSAPI和appid已设定，此参数必传
        :key sub_user_id: 可选，小程序appid下的唯一标识。trade_type=JSAPI和sub_appid已设定，此参数必传
        :key out_trade_no: 可选，商户订单号，默认自动生成
        :key detail: 可选，商品详情
        :key attach: 可选，附加数据，在查询API和支付通知中原样返回，该字段主要用于商户携带订单的自定义数据
        :key fee_type: 可选，符合ISO 4217标准的三位字母代码，默认人民币：CNY
        :key time_start: 可选，订单生成时间，默认为当前时间
        :key time_expire: 可选，订单失效时间，默认为订单生成时间后两小时
        :key goods_tag: 可选，商品标记，代金券或立减优惠功能的参数
        :key product_id: 可选，trade_type=NATIVE，此参数必传。此id为二维码中包含的商品ID，商户自行定义
        :key device_info: 可选，终端设备号(门店号或收银设备ID)，注意：PC网页或公众号内支付请传"WEB"
        :key limit_pay: 可选，指定支付方式，no_credit--指定不能使用信用卡支付
        :key scene_info: 可选，上报支付的场景信息
        :type scene_info: dict
        :param openid:
        :param trade_type:
        :return:
        """
        if not isinstance(product_dict, dict):
            raise RuntimeError("arg product_dict must be a dict")
        if "out_trade_no" not in product_dict:
            raise RuntimeError("miss out_trade_no")
        if "body" not in product_dict:
            raise RuntimeError("miss body")
        if "total_fee" not in product_dict:
            raise RuntimeError("miss total_fee")
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
        resp_json =  await self.execute('https://api.mch.weixin.qq.com/pay/unifiedorder',
                                            method="post",
                                            data=_body,
                                            resp_body_handler=self._handle_resp_result)
        return resp_json

    def _handle_resp_result(self, resp_body, raise_exception=None, error_msg="resp error"):
        """
        统一下单结果处理
        :param resp_body:
        :return:
        """
        resp_json = self.parse_xml(resp_body)
        if resp_json['return_code'] == AsyncClient.CODE_SUCCESS and resp_json["result_code"] == AsyncClient.CODE_SUCCESS:
            return resp_json
        if raise_exception is None:
            raise RuntimeError(error_msg)
        else:
            raise raise_exception(error_msg)


    async def query_order(self, transaction_id, appid):
        """
        订单查询
        详细规则参考 https://pay.weixin.qq.com/wiki/doc/api/app/app.php?chapter=9_2&index=4
        :param transaction_id:
        :param appid:
        :return:
        """

        body = {"transaction_id" : transaction_id,
                "appid": appid,
                "mch_id" : self._mch_id,
                "nonce_tr" : self._nonce_str_func()}
        xml_body = self.generate_xml(body)
        resp_json = await self.execute("https://api.mch.weixin.qq.com/pay/orderquery",
                                  method="post",
                                  data=xml_body,
                                  resp_body_handler=self._handle_resp_result)
        return resp_json

    async def close_order(self, out_trade_no):
        """
        关闭订单
        详细规则参考 https://pay.weixin.qq.com/wiki/doc/api/jsapi.php?chapter=9_3
        :param out_trade_no:
        :return:
        """
        body = {"out_trade_no" : out_trade_no,
                "appid": self._appid,
                "mch_id": self._mch_id,
                "nonce_str": self._nonce_str_func()}
        xml_body = self.generate_xml(body)
        resp_json = await self.execute("https://api.mch.weixin.qq.com/pay/closeorder",
                                 method="post",
                                 data=xml_body,
                                 resp_body_handler=self._handle_resp_result)
        return resp_json

    async def refund_order(self, transaction_id, op_user_id, out_refund_no=None):
        """
        申请退款
        详细规则参考 https://pay.weixin.qq.com/wiki/doc/api/jsapi.php?chapter=9_4

        out_trade_no: 商户订单号
        transaction_id: 微信订单号
        out_refund_no: 商户退款单号（若未传入则自动生成）
        total_fee: 订单金额
        refund_fee: 退款金额
        :param transaction_id:
        :param op_user_id:
        :param out_refund_no
        :return:
        """
        if not self._ssl_context:
            raise RuntimeError("need ssl")

        body = {"transaction_id": transaction_id,
                "mch_id": self._mch_id,
                "op_user_id": op_user_id,
                "nonce_str": self._nonce_str_func(),
                "appid" : self._appid,
                "out_refund_no": out_refund_no}
        xml_body = self.generate_xml(body)
        resp_json = await self.execute("https://api.mch.weixin.qq.com/secapi/pay/refund",
                                 method="post",
                                 data=xml_body,
                                 ssl=self._ssl_context,
                                 resp_body_handler=self._handle_resp_result)
        return resp_json

    async def query_refund(self, transaction_id):
        """
        查询退款
        提交退款申请后，通过调用该接口查询退款状态。退款有一定延时，
        用零钱支付的退款20分钟内到账，银行卡支付的退款3个工作日后重新查询退款状态。
        详细规则参考 https://pay.weixin.qq.com/wiki/doc/api/jsapi.php?chapter=9_5
            data: out_refund_no、out_trade_no、transaction_id、refund_id四个参数必填一个
            out_refund_no: 商户退款单号
            out_trade_no: 商户订单号
            transaction_id: 微信订单号
            refund_id: 微信退款单号
        :param transaction_id: 微信订单号
        :return:
        """
        body = {
            "transaction_id" : transaction_id,
            "appid" : self._appid,
            "mch_id" : self._mch_id,
            "nonce_str" : self._nonce_str_func()
        }
        xml_body = self.generate_xml(body)
        resp_json = await self.execute("https://api.mch.weixin.qq.com/secapi/pay/refundquery",
                                 method="post",
                                 data=xml_body,
                                 resp_body_handler=self._handle_resp_result)
        return resp_json

    async def enterprise_pay(self, partner_trade_no, amount, openid, desc, re_user_name=None, check_name="FORCE_CHECK"):
        """
        使用企业对个人付款功能
        详细规则参考 https://pay.weixin.qq.com/wiki/doc/api/tools/mch_pay.php?chapter=14_2
        :param partner_trade_no:
        :param amount:
        :param openid:
        :param desc:
        :param re_user_name:
        :param check_name:
        :return:
        """
        if not self._ssl_context:
            raise RuntimeError("need ssl")
        if check_name not in ("FORCE_CHECK", "NO_CHECK"):
            check_name = "FORCE_CHECK"

        body = {
            "mch_appid" : self._appid,
            "mchid": self._mch_id,
            "nonce_str" : self._nonce_str_func(),
            "amount" : amount,
            "partner_trade_no" : partner_trade_no,
            "openid" : openid,
            "desc" : desc,
            "check_name": check_name
        }
        if check_name == "FORCE_CHECK":
            body["re_user_name"] = re_user_name

        xml_body = self.generate_xml(body)
        resp_json = await self.execute("https://api.mch.weixin.qq.com/mmpaymkttransfers/promotion/transfers",
                                       method="post",
                                       data=xml_body,
                                       ssl=self._ssl_context,
                                       resp_body_handler=self._handle_resp_result)
        return resp_json