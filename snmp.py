import re
import subprocess
from collections import defaultdict

from netaddr import IPAddress

import oid.cisco_catalyst
import oid.cisco_sg
import oid.general
from custom_modules.errors import Error, NonCriticalError
from custom_modules.log import logger

__version__ = '1.0.0'

# Класс для группировки регулярного выражения и формата его выводимого результата
class RegexAction:
    def __init__(self, pattern, action):
        self.pattern = pattern
        self.action = action


class Interface:
    def __init__(self, index, ip_address=None, mask=None, name=None, MTU=None, MAC=None, mode=None, untagged=None, tagged=None, type=None):
        self.ip_address = ip_address
        self.mask = mask
        self.index = index
        self.name = name
        self.mtu = MTU
        self.mac_address = MAC
        self.mode = mode
        self.type = type
        self.untagged = untagged
        self.tagged = tagged

        # Преобразование IP-адреса и маски в префикс
        if self.ip_address and self.mask:
            self.ip_with_prefix = f'{self.ip_address}/{IPAddress(self.mask).netmask_bits()}'

    # Временный для дебага - потом удалить
    def print_attributes(self, title=''):
        logger.debug(title)
        for attribute, value in self.__dict__.items():
            logger.debug(f"{attribute}: {value}")
        logger.debug('-' * 40)


class SNMPDevice:
    models = {}  # Dictionary for storing device's models

    @classmethod
    def load_models(cls, file_name):
        with open(file_name, 'r') as f:
            for line in f:
                model_type, models_line = line.split(':')
                cls.models.update(
                    {model_type: list(filter(None, models_line.rstrip().split(',')))})

    @classmethod
    def get_network_table(cls, ip_address, table_oid, table_tag, community_string='public'):
        logger.info(f'Getting {table_tag} table from GW {ip_address} ')
        snmp_session = cls(ip_address, community_string)
        table_data = snmp_session.snmpwalk(
            table_oid, table_tag, hex=True, ip_address=ip_address, community_string=community_string)
        logger.debug(f'Got {len(table_data)} {table_tag}s')

        return cls.__indexes_to_dict(table_data)

    def __init__(self, ip_address, community_string, arp_table=None):
        self.community_string = community_string
        self.ip_address = ip_address
        self.arp_table = arp_table
        self.model_family = None

        self.model_families = {
            "cisco_catalyst": self.find_interfaces_cisco_catalyst,
            "cisco_sg_300": self.find_interfaces_cisco_sg,
            "cisco_sg_350": self.find_interfaces_cisco_sg,
            # "huawei": self.find_interfaces_huawei,
            # "zyxel": self.find_interfaces_zyxel,
            # "ubiquiti": self.find_interfaces_ubiquiti,
        }

    def snmpwalk(self, input_oid, typeSNMP='', hex=False, community_string=None, ip_address=None, custom_option=None, timeout_process=None):
        out = []
        # Список OID-ов, которым можно возвращать пустой список
        permissible_oids = [oid.general.model,
                            oid.general.lldp_rem_port,
                            oid.general.lldp_rem_name,
                            ]

        # Use self.community_string if community_string is not provided
        community_string = community_string or self.community_string
        # Use self.ip_address if ip_address is not provided
        ip_address = ip_address or self.ip_address

        try:
            process = ["snmpwalk", "-Pe", "-v", "2c", "-c", community_string, f"-On{'x' if hex else ''}",
                       *([custom_option] if custom_option else []), ip_address, *([input_oid] if input_oid else [])]

            result = subprocess.run(
                process, capture_output=True, text=True, timeout=timeout_process)

            # Обработка ошибок
            if result.returncode != 0:
                raise Error(
                    f'Fail SNMP (oid {input_oid})! Return code: {result.returncode}', ip_address)
            elif 'No Such Object' in result.stdout:
                raise NonCriticalError(
                    f'No Such Object available on this agent at this OID ({input_oid})', ip_address)
            elif 'No Such Instance currently exists' in result.stdout:
                raise NonCriticalError(
                    f'No Such Instance currently exists at this OID ({input_oid})', ip_address)

            # Словарь паттернов парсинга
            regex_actions = {
                'Debug': RegexAction(
                    r'(.*)',
                    lambda re_out: re_out.group(1)
                ),
                'DotSplit': RegexAction(
                    r'"([A-Za-z0-9\-_]+)(\.|\")',
                    lambda re_out: re_out.group(1)
                ),
                'IP': RegexAction(
                    r': (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                    lambda re_out: re_out.group(1)
                ),
                'INT': RegexAction(
                    r': (\d+)',
                    lambda re_out: re_out.group(1)
                ),
                'INDEX-INT': RegexAction(
                    r'.(\d+) = \w+: (\d+)',
                    lambda re_out: [re_out.group(1), re_out.group(2)]
                ),
                'INDEX-MAC': RegexAction(
                    r'.(\d+) = [\w\-]+: (([0-9A-Fa-f]{2} ?){6})',
                    lambda re_out: [re_out.group(1), re_out.group(
                        2).strip().replace(" ", ':').upper()]
                ),
                'PREINDEX-MAC': RegexAction(
                    r'.(\d+).\d+ = [\w\-]+: (([0-9A-Fa-f]{2} ?){6}) ?$',
                    lambda re_out: [re_out.group(
                        1), re_out.group(2).strip().upper()]
                ),
                'IP-MAC': RegexAction(
                    r'.(\d+.\d+.\d+.\d+) = [\w\-]+: (([0-9A-Fa-f]{2} ?){6})',
                    lambda re_out: [re_out.group(1), re_out.group(
                        2).strip().replace(" ", ':').upper()]
                ),
                'IP-MASK': RegexAction(
                    r'.(\d+.\d+.\d+.\d+) = [\w\-]+: (\d+.\d+.\d+.\d+)',
                    lambda re_out: [re_out.group(1), re_out.group(2)]
                ),

                'INDEX-DESC': RegexAction(
                    r'.(\d+) = [\w\-]*:? ?"([^"]*)"',
                    lambda re_out: [re_out.group(1), re_out.group(2)]
                ),
                'PREINDEX-DESC': RegexAction(
                    r'.(\d+).\d+ = [\w\-]*:? ?"([A-Za-z0-9\/\-_]*)(?:\.[^"]*)?"',
                    lambda re_out: [re_out.group(1), re_out.group(2)]
                ),
                'INDEX-HEX': RegexAction(
                    r'.(\d+) = [\w\-]+: (([0-9A-Fa-f]{2} ?\n?){1,})',
                    lambda re_out: [re_out.group(1),
                                    re_out.group(2).strip().replace(" ", '').replace("\n", '').upper()]
                ),
                'INDEX-DESC-HEX': RegexAction(
                    r'.(\d+) = [\w\-]*:? ?"?(([0-9A-Fa-f]{2} ?\n?)*)"?',
                    lambda re_out: [re_out.group(1),
                                    re_out.group(2).strip().replace("\n", '').upper()]
                ),
                'MAC': RegexAction(
                    r': (([0-9A-Fa-f]{2} ?){6})',
                    lambda re_out: re_out.group(
                        1).strip().replace(" ", ':').upper()
                ),
                'DEFAULT': RegexAction(
                    r'"([^"]*)"',
                    lambda re_out: re_out.group(1)
                )
            }

            # Выбор паттерна по параметру typeSNMP
            regex_action = regex_actions.get(
                typeSNMP, regex_actions['DEFAULT'])

            # Если вывод snmpwalk не пустой (больше чем 1 символ - '.')
            if len(result.stdout) > 0:
                # Построчно обрабатываем вывод snmpwalk
                for lineSNMP in result.stdout[1:].split('\n.'):
                    # Игнорируем пустые строки
                    if not lineSNMP:
                        continue

                    re_out = re.search(regex_action.pattern, lineSNMP)
                    # Игнорируем строки при НЕ нахождении паттерна
                    if re_out:
                        output = regex_action.action(re_out)
                        # Собираем результаты в список out
                        out += [output]

            # if len(out) == 0 and input_oid not in permissible_oids:
            #     raise Error(f'{input_oid} вернул пустой список')

            return out

        except subprocess.TimeoutExpired as timeErr:
            if len(timeErr.stdout) > 0:
                for lineSNMP in timeErr.stdout[1:].split('\n.'):
                    if not lineSNMP:
                        continue
                    out += [lineSNMP]
            raise Error(f'Timeout Expired: {str(timeErr)}')

        except NonCriticalError:
            return out
        except Error:
            raise  # Re-raise the specific error without further handling

        except Exception as e:
            raise Error(f'Unexpected error: {str(e)}')

    def get_hostname(self):
        logger.info('Getting hostname from SNMP...')
        value = self.snmpwalk(oid.general.hostname, 'DotSplit')
        self.hostname = value[0]
        return self.hostname

    def get_model(self):
        logger.info('Getting model from SNMP...')
        
        model, model_alternative = oid.general.model, oid.general.alt_model 
        regexp_primary, regexp_alternative = r'(\b[A-Z][A-Z0-9]{2,5}-[A-Z0-9]{1,4}-?[A-Z0-9\/]{1,5}\b)', r'MN:(\S+)'

        for mod in [model, model_alternative]:
            value = self.snmpwalk(mod)
            if value:
                for regex in [regexp_primary, regexp_alternative]:
                    result = re.search(regex, value[0])
                    if result:
                        self.model = result.group(1)
                        return self.model
                if mod == model_alternative:
                    self.model = next((i for i in value if i), None)
                    if self.model: return self.model
        
        raise Error("Model is undefined")

    def get_serial_number(self):
        logger.info('Getting serial number from SNMP...')
        value = self.snmpwalk(oid.general.serial_number)
        self.serial_number = next((i for i in value if i), None)
        return self.serial_number

    def get_virtual_interfaces(self):
        logger.info('Getting virtual interfaces from SNMP...')
        ip_addresses = self.snmpwalk(oid.general.svi_ip_addresses, 'IP')
        masks = self.snmpwalk(oid.general.svi_masks, 'IP')
        indexes = self.snmpwalk(oid.general.svi_indexes, 'INT')

        SVIs = []
        for i, index in enumerate(indexes):
            if masks[i] == '0.0.0.0':
                continue

            name = self.snmpwalk(f"{oid.general.si_int_name}.{index}")
            MTU = self.snmpwalk(f"{oid.general.si_mtu}.{index}", 'INT')
            MAC = self.snmpwalk(
                f"{oid.general.si_mac}.{index}", 'MAC', hex=True)

            SVIs += [Interface(
                ip_address=ip_addresses[i],
                mask=masks[i],
                index=index,
                name=name[0] if name else None,
                MTU=MTU[0] if MTU else None,
                MAC=MAC[0] if MAC else None,
                type='virtual',
            )]

            SVIs[-1].print_attributes('SVI:')
        return SVIs

    def find_model_family(self):
        logger.info('Finding model family...')
        for model_family, models in SNMPDevice.models.items():
            if self.model in models:
                self.model_family = model_family
                return self.model_family

        NonCriticalError(f"{self.model} не найдена в models.list", self.ip_address)
        return None

#   БЛОК ПОЛУЧЕНИЯ ИНТЕРФЕЙСОВ
# ========================================================================
    def get_physical_interfaces(self):
        # Helper functions
        # ========================================================================
        def get_lldp_data_by_index(int_name_dict, lldp_loc_port_dict, lldp_data_dict):
            """
            Get LLDP data by index from dictionaries of interface names and LLDP data.
            """
            lldp_data_by_index = {}
            for int_index, int_name in int_name_dict.items():
                lldp_index = next((idx for idx, name in lldp_loc_port_dict.items(
                ) if name.startswith(int_name)), None)
                if lldp_index:
                    lldp_data = lldp_data_dict.get(lldp_index)
                    if lldp_data:
                        lldp_data_by_index[int_index] = lldp_data
            return lldp_data_by_index

        def get_snmp_data(oid, data_type, hex_output=False):
            """
            Get SNMP data using specified OIDs, data type, and optional hex_output.
            """
            output = self.snmpwalk(oid, typeSNMP=data_type, hex=hex_output)
            cleaned_output = ([index, value]
                              for index, value in output if value != '')
            return self.__indexes_to_dict(cleaned_output)

        def hex2string(hex_value):
            """
            Convert hex value to string, handling encoding properly.
            """
            return "".join([chr(int(x, 16)) for x in hex_value.split()]).encode('latin1').decode('utf-8') if hex_value else ""

        # Main logic
        # ========================================================================
        logger.info('Getting physical interfaces...')
        
        int_name_dict = get_snmp_data(oid.general.si_int_name, 'INDEX-DESC')
        mtu_dict = get_snmp_data(oid.general.si_mtu, 'INDEX-INT')
        status_dict = get_snmp_data(oid.general.si_status, 'INDEX-INT')
        mac_dict = get_snmp_data(
            oid.general.si_mac, 'INDEX-MAC', hex_output=True)
        desc_dict = get_snmp_data(
            oid.general.si_description, 'INDEX-DESC-HEX', hex_output=True)
        lldp_loc_port_dict = get_snmp_data(
            oid.general.lldp_loc_port, 'INDEX-DESC')
        lldp_rem_name_dict = get_snmp_data(
            oid.general.lldp_rem_name, 'PREINDEX-DESC')

        lldp_rem_name_by_index = get_lldp_data_by_index(
            int_name_dict, lldp_loc_port_dict, lldp_rem_name_dict)
        lldp_rem_port_dict = get_snmp_data(
            oid.general.lldp_rem_port, 'PREINDEX-DESC')
        lldp_rem_port_by_index = get_lldp_data_by_index(
            int_name_dict, lldp_loc_port_dict, lldp_rem_port_dict)
        lldp_rem_mac_dict = get_snmp_data(
            oid.general.lldp_rem_mac, 'PREINDEX-MAC', hex_output=True)
        lldp_rem_mac_by_index = get_lldp_data_by_index(
            int_name_dict, lldp_loc_port_dict, lldp_rem_mac_dict)
        
        if self.model_family:
            get_interfaces_func = self.model_families.get(self.model_family)
            if get_interfaces_func:
                interfaces = get_interfaces_func()
                if not interfaces:
                    raise Error(
                        f"get_interfaces_func() вернула пустой список интерфейсов")
        else:
            interfaces = []
            for key in int_name_dict.keys():
                interfaces.append(Interface(
                    index=key,
                ))

        for interface in interfaces:
            interface.name = int_name_dict[interface.index]
            mtu_value = mtu_dict.get(interface.index)
            if mtu_value is not None and int(mtu_value) >= 1:    # mtu должен быть больше 0
                interface.mtu = mtu_value
            interface.status = status_dict[interface.index]
            interface.mac_address = mac_dict.get(interface.index)
            if interface.status == '1':
                interface.description = hex2string(desc_dict.get(interface.index))

            lldp_rem_name = lldp_rem_name_by_index.get(interface.index)
            lldp_rem_mac = lldp_rem_mac_by_index.get(
                interface.index, '').replace(" ", ':').upper()
            lldp_rem_port = lldp_rem_port_by_index.get(interface.index)
            if self.arp_table:
                interface.rem_ip = next(
                    (key for key, value in self.arp_table.items() if value == lldp_rem_mac), None)

            interface.lldp_rem = {
                "name": lldp_rem_name,
                "mac": lldp_rem_mac,
                "port": lldp_rem_port,
            }
            # Предполагаем, что интерфейсы начинающиеся с "P" являются LAG
            if interface.name[0].lower() == 'p':
                interface.type = 'lag'

            interface.print_attributes('Interface:')
        return interfaces

# Вендорозависимые методы интерфейсов
# ========================================================================
    def find_interfaces_cisco_catalyst(self):
        interfaces = []
        try:
            mode_port_dict = self.__get_snmp_dict(
                oid.cisco_catalyst.mode_port, 'INDEX-INT')
            native_port_dict = self.__get_snmp_dict(
                oid.cisco_catalyst.native_port, 'INDEX-INT')
            untag_port_dict = self.__get_snmp_dict(
                oid.cisco_catalyst.untag_port, 'INDEX-INT')
            tag_port_dict = self.__get_tag_dict_by_port(
                oid.cisco_catalyst.hex_tag_port)
            tag_noneg_port_dict = self.__get_tag_dict_by_port(
                oid.cisco_catalyst.hex_tag_noneg_port)
        except NonCriticalError as e:
            NonCriticalError.store_error(self.ip_address, str(e))

        for index, value in mode_port_dict.items():
            if value in oid.cisco_catalyst.mode_port_state["access"]:
                interfaces.append(
                    self.__create_interface_access(index, untag_port_dict))
            elif value in oid.cisco_catalyst.mode_port_state["tagged"]:
                interfaces.append(self.__create_interface_tagged(
                    index, native_port_dict, tag_port_dict))
            elif value in oid.cisco_catalyst.mode_port_state["tagged-noneg"]:
                interfaces.append(self.__create_interface_tagged(
                    index, native_port_dict, tag_noneg_port_dict))

        return interfaces

    def find_interfaces_cisco_sg(self):
        """
        Finds and creates network interfaces for Cisco SG switches based on SNMP data.
        Returns:
            List of interface objects created using SNMP data.
        """
        interfaces = []

        try:
            mode_port_dict = self.__get_snmp_dict(
                oid.cisco_sg.mode_port, 'INDEX-INT')
            untag_port_dict = self.__get_snmp_dict(
                oid.cisco_sg.untag_port[self.model_family], 'INDEX-INT')
            tag_port_dict = self.__get_tag_dict_by_vlan(
                oid.cisco_sg.hex_tag_port)
        except NonCriticalError as e:
            NonCriticalError.store_error(self.ip_address, str(e))

        for index, value in mode_port_dict.items():
            if value == oid.cisco_sg.mode_port_state[self.model_family]["access"]:
                interfaces.append(
                    self.__create_interface_access(index, untag_port_dict))
            elif value == oid.cisco_sg.mode_port_state[self.model_family]["tagged"]:
                interfaces.append(self.__create_interface_tagged(
                    index, untag_port_dict, tag_port_dict))
                # Check if the last interface has both tagged and untagged VLANs,
                # and if the untagged VLAN is also in the tagged VLANs list
                if (interfaces[-1].tagged
                    and interfaces[-1].untagged
                        and interfaces[-1].untagged in interfaces[-1].tagged):
                    # If yes, remove the untagged VLAN from the tagged VLANs list
                    interfaces[-1].tagged.remove(interfaces[-1].untagged)

        return interfaces

    def find_interfaces_huawei(self):
        pass

    def find_interfaces_zyxel(self):
        pass

    def find_interfaces_ubiquiti(self):
        pass

#   Хэлпер-методы
# ========================================================================
    def __get_snmp_dict(self, oid, snmp_type):
        """
        This is a helper function that uses SNMP to get a dictionary of the specified OID.
        """
        output = self.snmpwalk(oid, snmp_type)
        return self.__indexes_to_dict(output)

    @staticmethod
    def __indexes_to_dict(indexes):
        """
        Converts a list of tuples to a dictionary where the first item of each tuple is the key and the second item is the value.
        If multiple tuples have the same key, the values are concatenated into a string.
        """
        result_dict = {}
        for interface, value in indexes:
            if interface in result_dict:
                result_dict[interface] += ", " + value
            else:
                result_dict[interface] = value
        return result_dict

    def __get_tag_dict_by_port(self, oid):
        """
        Метод для получения порт:влан словаря, для случаев, когда список вланов храниться в HEX
        """
        output = self.snmpwalk(oid, 'INDEX-HEX', True)
        tag_dict = defaultdict(list)
        for port_index, hex_vlans in output:
            for vid in self.__hex_to_binary_list(hex_vlans, 0):
                if vid == '1':
                    continue
                tag_dict[port_index].append(vid)
        return tag_dict

    def __get_tag_dict_by_vlan(self, oid):
        """
        Метод для получения порт:влан словаря, для случаев, когда список портов храниться в HEX
        """
        output = self.snmpwalk(oid, 'INDEX-HEX')

        tag_dict = defaultdict(list)
        for vlan_id, hex_indexes in output:
            if vlan_id == '1':
                continue
            for interface_index in self.__hex_to_binary_list(hex_indexes):
                tag_dict[interface_index].append(vlan_id)

        return tag_dict

    def __hex_to_binary_list(self, hex_str, inc=1):
        binary_str = self.__hex_to_binary(hex_str)
        return self.__binary_to_list(binary_str, inc)

    @staticmethod
    def __hex_to_binary(hex_str):
        # Преобразует шестнадцатеричное число в двоичное и удаляет префикс '0b'
        binary_str = bin(int(hex_str, 16))[2:]
        # Дополняем нулями слева, чтобы каждый шестнадцатеричный символ соответствовал 4 двоичным
        binary_str = binary_str.zfill(len(hex_str) * 4)
        return binary_str

    @staticmethod
    def __binary_to_list(binary_str, inc=1):
        return [str(i + inc) for i, bit in enumerate(binary_str) if bit == '1']

    def __create_interface_access(self, index, untag_port_dict):
        """
        This is a helper function that creates an access interface object.
        """
        return Interface(
            index=index,
            untagged=untag_port_dict[index] if index in untag_port_dict and untag_port_dict[index] not in (
                '0', '1') else None,
            mode='access',
        )

    def __create_interface_tagged(self, index, native_port_dict, tag_dict):
        """
        This is a helper function that creates a tagged interface object.
        """
        untagged = native_port_dict.get(index)
        if untagged in ('1', '0'):
            untagged = None

        tagged = tag_dict.get(index, [])
        mode = 'tagged'
        if (len(tagged) == 1 and tagged[0] == untagged) or not tagged:
            mode = 'tagged-all'
        return Interface(index=index, untagged=untagged, mode=mode, tagged=tagged)
# ========================================================================
