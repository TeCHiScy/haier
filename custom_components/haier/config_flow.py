import logging
import time
from dataclasses import dataclass
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.config_entries import ConfigFlowResult
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.config_validation import multi_select

from .const import (
    CONFIG_ENTRY_VERSION,
    DOMAIN,
    FILTER_TYPE_EXCLUDE,
    FILTER_TYPE_INCLUDE,
)
from .core.client import HaierClientException, HaierClient, APP_SOURCE_APP, APP_SOURCE_WXAPP, DEFAULT_APP_SOURCE
from .core.config import (
    AccountConfig,
    DeviceFilterConfig,
    EntityFilterConfig,
    PreferencesConfig,
)

_LOGGER = logging.getLogger(__name__)

CLIENT_ID = 'client_id'
REFRESH_TOKEN = 'refresh_token'
APP_SOURCE = 'app_source'

APP_SOURCE_OPTIONS = {
    APP_SOURCE_WXAPP: '微信小程序',
    APP_SOURCE_APP: 'App',
}


@dataclass(frozen=True)
class AuthenticationResult:
    """认证成功结果。"""

    account: dict[str, Any]
    mobile: str


class LoginFlowMixin:
    """复用登录方式菜单、表单和认证处理。"""

    # 下列属性/方法由宿主 flow 类（ConfigFlow / OptionsFlow）提供，这里只做类型声明。
    hass: HomeAssistant
    async_show_form: Any
    async_show_menu: Any
    async_abort: Any
    async_create_entry: Any
    async_update_reload_and_abort: Any

    # 短信登录的中间状态：已发码的手机号
    _sms_phone: str | None = None

    async def _async_phone_login_form(
        self,
        step_id: str,
        user_input: dict[str, Any] | None,
    ) -> ConfigFlowResult | AuthenticationResult:
        errors: dict[str, str] = {}
        description_placeholders: dict[str, str] = {}

        if user_input is not None:
            try:
                phone = user_input['phone']
                client = HaierClient(self.hass, phone, '', APP_SOURCE_APP)
                token_info = await client.phone_login(
                    phone, user_input['password']
                )
                client = HaierClient(
                    self.hass, phone, token_info.token, APP_SOURCE_APP
                )
                user_info = await client.get_user_info()

                return AuthenticationResult(
                    account={
                        'client_id': phone,
                        'token': token_info.token,
                        'refresh_token': token_info.refresh_token,
                        'expires_at': int(time.time()) + token_info.expires_in,
                        'app_source': APP_SOURCE_APP,
                    },
                    mobile=user_info['mobile']
                )
            except HaierClientException as e:
                _LOGGER.warning(str(e))
                errors['base'] = 'auth_error'
                description_placeholders['reason'] = str(e)

        return self.async_show_form(
            step_id=step_id,
            data_schema=vol.Schema(
                {
                    vol.Required('phone'): str,
                    vol.Required('password'): str,
                }
            ),
            errors=errors,
            description_placeholders=description_placeholders
        )

    async def _async_sms_phone_form(
        self,
        step_id: str,
        user_input: dict[str, Any] | None,
    ) -> ConfigFlowResult | None:
        """短信登录第一步：收集手机号并发送验证码。发送成功返回 None。"""
        errors: dict[str, str] = {}
        description_placeholders: dict[str, str] = {}

        if user_input is not None:
            try:
                phone = user_input['phone']
                # 短信登录只能用 wxapp 来源：refresh_token 与签发它的 appId 绑定
                client = HaierClient(self.hass, phone, '', APP_SOURCE_WXAPP)
                await client.send_sms_code(phone)
                self._sms_phone = phone
                return None
            except HaierClientException as e:
                _LOGGER.warning(str(e))
                errors['base'] = 'sms_send_error'
                description_placeholders['reason'] = str(e)

        return self.async_show_form(
            step_id=step_id,
            data_schema=vol.Schema({vol.Required('phone'): str}),
            errors=errors,
            description_placeholders=description_placeholders
        )

    async def _async_sms_code_form(
        self,
        step_id: str,
        user_input: dict[str, Any] | None,
    ) -> ConfigFlowResult | AuthenticationResult:
        """短信登录第二步：用验证码换 token 并拉取用户信息。"""
        errors: dict[str, str] = {}
        description_placeholders: dict[str, str] = {}
        phone = getattr(self, '_sms_phone', None)

        if phone is None:
            return self.async_abort(reason='sms_flow_expired')

        if user_input is not None:
            try:
                client = HaierClient(self.hass, phone, '', APP_SOURCE_WXAPP)
                token_info = await client.phone_sms_login(phone, user_input['sms_code'])
                client = HaierClient(
                    self.hass, phone, token_info.token, APP_SOURCE_WXAPP
                )
                user_info = await client.get_user_info()

                return AuthenticationResult(
                    account={
                        'client_id': phone,
                        'token': token_info.token,
                        'refresh_token': token_info.refresh_token,
                        'expires_at': int(time.time()) + token_info.expires_in,
                        'app_source': APP_SOURCE_WXAPP,
                    },
                    mobile=user_info['mobile']
                )
            except HaierClientException as e:
                _LOGGER.warning(str(e))
                errors['base'] = 'auth_error'
                description_placeholders['reason'] = str(e)

        return self.async_show_form(
            step_id=step_id,
            data_schema=vol.Schema({vol.Required('sms_code'): str}),
            errors=errors,
            description_placeholders={**description_placeholders, 'phone': phone}
        )

    async def _async_manual_login_form(
        self,
        step_id: str,
        user_input: dict[str, Any] | None,
        default_client_id: str | None = None,
        default_refresh_token: str | None = None,
        default_app_source: str = DEFAULT_APP_SOURCE,
    ) -> ConfigFlowResult | AuthenticationResult:
        errors: dict[str, str] = {}
        description_placeholders: dict[str, str] = {}

        if user_input is not None:
            try:
                client_id = user_input[CLIENT_ID]
                app_source = user_input[APP_SOURCE]
                client = HaierClient(self.hass, client_id, '', app_source)
                token_info = await client.refresh_token(
                    user_input[REFRESH_TOKEN]
                )
                client = HaierClient(
                    self.hass, client_id, token_info.token, app_source
                )
                user_info = await client.get_user_info()

                return AuthenticationResult(
                    account={
                        'client_id': client_id,
                        'token': token_info.token,
                        'refresh_token': token_info.refresh_token,
                        'expires_at': int(time.time()) + token_info.expires_in,
                        'app_source': app_source,
                    },
                    mobile=user_info['mobile']
                )
            except HaierClientException as e:
                _LOGGER.warning(str(e))
                errors['base'] = 'auth_error'
                description_placeholders['reason'] = str(e)

        client_id_field = (
            vol.Required(CLIENT_ID)
            if default_client_id is None
            else vol.Required(CLIENT_ID, default=default_client_id)
        )
        refresh_token_field = (
            vol.Required(REFRESH_TOKEN)
            if default_refresh_token is None
            else vol.Required(REFRESH_TOKEN, default=default_refresh_token)
        )
        return self.async_show_form(
            step_id=step_id,
            data_schema=vol.Schema(
                {
                    client_id_field: str,
                    refresh_token_field: str,
                    vol.Required(
                        APP_SOURCE, default=default_app_source
                    ): vol.In(APP_SOURCE_OPTIONS),
                }
            ),
            errors=errors,
            description_placeholders=description_placeholders
        )


class HaierConfigFlow(LoginFlowMixin, config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = CONFIG_ENTRY_VERSION

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """选择登录方式"""
        return self.async_show_menu(
            step_id="user",
            menu_options=['sms_login', 'phone_login', 'manual']
        )

    async def async_step_manual(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        result = await self._async_manual_login_form('manual', user_input)
        if not isinstance(result, AuthenticationResult):
            return result

        return self.async_create_entry(
            title="Haier - {}".format(result.mobile),
            data={
                'account': result.account
            }
        )

    async def async_step_phone_login(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """手机号+密码登录"""
        result = await self._async_phone_login_form('phone_login', user_input)
        if not isinstance(result, AuthenticationResult):
            return result

        return self.async_create_entry(
            title="Haier - {}".format(result.mobile),
            data={
                'account': result.account
            }
        )

    async def async_step_sms_login(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """手机号+短信验证码登录（第一步：手机号）"""
        form = await self._async_sms_phone_form('sms_login', user_input)
        if form is not None:
            return form

        return await self.async_step_sms_login_code()

    async def async_step_sms_login_code(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """手机号+短信验证码登录（第二步：验证码）"""
        result = await self._async_sms_code_form('sms_login_code', user_input)
        if not isinstance(result, AuthenticationResult):
            return result

        return self.async_create_entry(
            title=f"Haier - {result.mobile}",
            data={
                'account': result.account
            }
        )

    async def async_step_reauth(self, entry_data: dict[str, Any]) -> ConfigFlowResult:
        """refresh_token 失效后重新认证：从头走一遍短信登录"""
        self._sms_phone = None
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """重新认证（第一步：手机号）"""
        form = await self._async_sms_phone_form('reauth_confirm', user_input)
        if form is not None:
            return form

        return await self.async_step_reauth_sms_code()

    async def async_step_reauth_sms_code(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """重新认证（第二步：验证码）"""
        result = await self._async_sms_code_form('reauth_sms_code', user_input)
        if not isinstance(result, AuthenticationResult):
            return result

        entry_id = self.context.get('entry_id')
        entry = self.hass.config_entries.async_get_entry(entry_id) if entry_id else None
        if entry is None:
            return self.async_abort(reason='reauth_entry_missing')

        return self.async_update_reload_and_abort(
            entry,
            title=f"Haier - {result.mobile}",
            data={
                'account': result.account
            }
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: config_entries.ConfigEntry) -> config_entries.OptionsFlow:
        return OptionsFlowHandler(config_entry)


class OptionsFlowHandler(LoginFlowMixin, config_entries.OptionsFlow):
    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        self._config_entry = config_entry

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """
        功能菜单
        :param user_input:
        :return:
        """
        return self.async_show_menu(
            step_id="init",
            menu_options=['account', 'device', 'entity_device_selector', 'preferences']
        )

    async def async_step_account( self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """选择账户登录方式。"""
        return self.async_show_menu(
            step_id="account",
            menu_options=['account_sms_login', 'account_phone_login', 'account_manual']
        )

    async def _async_save_account_authentication(
        self, result: AuthenticationResult
    ) -> ConfigFlowResult:
        """保存更新后的账户认证信息。"""
        cfg = AccountConfig(self.hass, self.config_entry)
        cfg.client_id = result.account['client_id']
        cfg.token = result.account['token']
        cfg.refresh_token = result.account['refresh_token']
        cfg.expires_at = result.account['expires_at']
        cfg.app_source = result.account['app_source']
        cfg.save(result.mobile)

        await self.hass.config_entries.async_reload(self.config_entry.entry_id)

        return self.async_create_entry(title='', data={})

    async def async_step_account_phone_login(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """使用手机号和密码更新账户。"""
        result = await self._async_phone_login_form(
            'account_phone_login', user_input
        )
        if not isinstance(result, AuthenticationResult):
            return result

        return await self._async_save_account_authentication(result)

    async def async_step_account_sms_login(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """使用手机号+短信验证码更新账户（第一步：手机号）。"""
        form = await self._async_sms_phone_form('account_sms_login', user_input)
        if form is not None:
            return form

        return await self.async_step_account_sms_login_code()

    async def async_step_account_sms_login_code(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """使用手机号+短信验证码更新账户（第二步：验证码）。"""
        result = await self._async_sms_code_form('account_sms_login_code', user_input)
        if not isinstance(result, AuthenticationResult):
            return result

        return await self._async_save_account_authentication(result)

    async def async_step_account_manual(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """使用 Refresh Token 更新账户。"""
        cfg = AccountConfig(self.hass, self.config_entry)
        result = await self._async_manual_login_form(
            'account_manual',
            user_input,
            default_client_id=cfg.client_id,
            default_refresh_token=cfg.refresh_token,
            default_app_source=cfg.app_source
        )
        if not isinstance(result, AuthenticationResult):
            return result

        return await self._async_save_account_authentication(result)

    async def async_step_preferences(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """偏好设置。"""
        cfg = PreferencesConfig(self.hass, self.config_entry)

        if user_input is not None:
            cfg.default_load_all_entity = user_input['default_load_all_entity']
            cfg.ignore_device_offline = user_input['ignore_device_offline']
            cfg.save()

            await self.hass.config_entries.async_reload(self.config_entry.entry_id)

            return self.async_create_entry(title='', data={})

        return self.async_show_form(
            step_id="preferences",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        'default_load_all_entity',
                        default=cfg.default_load_all_entity
                    ): bool,
                    vol.Required(
                        'ignore_device_offline',
                        default=cfg.ignore_device_offline
                    ): bool,
                }
            )
        )

    async def async_step_device(self,  user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """
        筛选设备
        :param user_input:
        :return:
        """
        cfg = DeviceFilterConfig(self.hass, self.config_entry)

        if user_input is not None:
            cfg.set_filter_type(user_input['filter_type'])
            cfg.set_target_devices(user_input['target_devices'])
            cfg.save()

            return self.async_create_entry(title='', data={})

        devices = {}
        for item in self.hass.data[DOMAIN]['devices']:
            devices[item.id] = item.name

        return self.async_show_form(
            step_id="device",
            data_schema=vol.Schema(
                {
                    vol.Required('filter_type', default=cfg.filter_type): vol.In({
                        FILTER_TYPE_EXCLUDE: 'Exclude',
                        FILTER_TYPE_INCLUDE: 'Include',
                    }),
                    vol.Optional('target_devices', default=cfg.target_devices): multi_select(devices)
                }
            )
        )

    async def async_step_entity_device_selector(self,  user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """
        筛选实体（设备选择）
        :param user_input:
        :return:
        """
        if user_input is not None:
            self.hass.data[DOMAIN]['entity_filter_target_device'] = user_input['target_device']
            return await self.async_step_entity_filter()

        devices = {}
        for item in self.hass.data[DOMAIN]['devices']:
            devices[item.id] = item.name

        return self.async_show_form(
            step_id="entity_device_selector",
            data_schema=vol.Schema(
                {
                    vol.Required('target_device'): vol.In(devices)
                }
            )
        )

    async def async_step_entity_filter(self,  user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """
        筛选实体
        :param user_input:
        :return:
        """
        cfg = EntityFilterConfig(self.hass, self.config_entry)

        if user_input is not None:
            cfg.set_filter_type(user_input['device_id'], user_input['filter_type'])
            cfg.set_target_entities(user_input['device_id'], user_input['target_entities'])
            cfg.save()

            await self.hass.config_entries.async_reload(self.config_entry.entry_id)

            return self.async_create_entry(title='', data={})

        target_device_id = self.hass.data[DOMAIN].pop('entity_filter_target_device', '')
        for device in self.hass.data[DOMAIN]['devices']:
            if device.id == target_device_id:
                target_device = device
                break
        else:
            raise ValueError('Device [{}] not found'.format(target_device_id))

        entities = {}
        for attribute in target_device.attributes:
            entities[attribute.key] = attribute.display_name

        filtered = [item for item in cfg.get_target_entities(target_device_id) if item in entities]

        return self.async_show_form(
            step_id="entity_filter",
            data_schema=vol.Schema(
                {
                    vol.Required('device_id', default=target_device_id): str,
                    vol.Required('filter_type', default=cfg.get_filter_type(target_device_id)): vol.In({
                        FILTER_TYPE_EXCLUDE: 'Exclude',
                        FILTER_TYPE_INCLUDE: 'Include',
                    }),
                    vol.Optional('target_entities', default=filtered): multi_select(
                        entities
                    )
                }
            )
        )
