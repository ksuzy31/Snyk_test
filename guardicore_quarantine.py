import json
import time
import requests
import urllib3
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CentraAPI():

    def __init__(self, hostname: str, username: str, password: str, access_token: str = None, **kwargs):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.access_token = access_token
        self.login_status = 0
        self.api_version = "v3.0"
        self.headers = {"Content-Type": "application/json"}

        self.session = None

        for key in kwargs:
            self.__dict__[key] = kwargs[key]

        if self.access_token == None:
            self.login()

    def login(self) -> int:
        """
        /api/v3.0/authenticate, with the following body: {"username": "<username>", "password": "<password>"}
        The response will be access_token: <token>"""
        try:
            with requests.session() as s:
                resp = requests.post(f"{self.hostname}/api/{self.api_version}/authenticate",
                                     data=json.dumps({"username": self.username, "password": self.password}),
                                     headers=self.headers, verify=False)

                if resp.status_code != 200:
                    self.login_status = -1
                    print(resp.content)
                else:
                    self.access_token = resp.json()['access_token']
                    self.login_status = 1
                    self.session = s
            """
            resp = requests.post(f"{self.hostname}/api/{self.api_version}/authenticate",
             data=json.dumps({"username": self.username, "password": self.password}),
             headers=self.headers, verify=False)

            if resp.status_code != 200:
                self.login_status = -1
            else:
                self.access_token = resp.json()['access_token']
                self.login_status = 1
            """
        except Exception as e:
            self.login_status = -1
            # TODO actually handle this error and parsing the payload above as well

        return self.login_status

    def login_success(self) -> bool:
        if self.login_status == 1 and self.access_token is not None:
            return True
        else:
            return False

    def api_assets_list_assets(self, history_len: int = 20) -> list:
        """
        Pulls all assets on an MGMT;
            0 will return all assets
        :param history_len:
        :return:
        """
        return self._pagination_get(f"{self.hostname}/api/{self.api_version}/assets",
                                    {"Authorization": f"Bearer {self.access_token}"})

    def api_assets_get_policy_for_asset(self, uuid: str) -> dict:
        """
        Get policy for assets
        :param uuid:
        :return:
        """

        resp = requests.get(f"{self.hostname}/api/{self.api_version}/assets" +
                            f"/{uuid}/policy",
                            headers={"Authorization": f"Bearer {self.access_token}"})
        if resp.status_code != 200:
            raise Exception("Unable to pull revisions from server.")

        return resp.json()

    def api_get_agent_policy_for_a_specific_asset(self, asset_id: str) -> dict:
        """
        Get policy for specific asset
        :param asset_id:
        :return:
        """
        resp = requests.get(f"{self.hostname}/api/{self.api_version}/assets" +
                            f"/{asset_id}/policy",
                            headers={"Authorization": f"Bearer {self.access_token}"})
        if resp.status_code != 200:
            raise Exception("Unable to pull revisions from server.")

        return resp.json()

    def api_list_agents(self) -> [dict]:
        return self._pagination_get(f"{self.hostname}/api/{self.api_version}/agents",
                                    {"Authorization": f"Bearer {self.access_token}"})

    def api_list_assets(self) -> [dict]:
        return self._pagination_get(f"{self.hostname}/api/{self.api_version}/assets",
                                    {"Authorization": f"Bearer {self.access_token}"})

    def api_list_labels(self, key, value):
        resp = requests.get(f"{self.hostname}/api/{self.api_version}/visibility/labels?key={key}&value={value}",
                            headers={"Authorization": f"Bearer {self.access_token}"},
                            verify=False)
        if resp.json() == "":
            return False
        else:
            respJ = resp.json()["objects"]
            if len(respJ) == 1:
                return respJ[0]
            else:
                return False
        #print(resp.json())
        #exit()
        # v3.0/visibility/labels?find_matches=true&dynamic_criteria_limit=5000&key=App&value=MsSQL&limit=100&offset=0

    # this method will only work 100% if adding by vm_ids or no vm_ids
    def api_add_label(self, key: str, value: str, vm_ids: [str]) -> bool:
        headers = {"Authorization": f"Bearer {self.access_token}",
                   'content-type': 'application/json'}
        resp = requests.post(f"{self.hostname}/api/{self.api_version}/assets/labels/{key}/{value}", data=json.dumps({
            "vms": vm_ids
        }),
                             headers=headers, verify=False)
        print(resp.content)
        if resp.status_code < 300:
            return resp.json(), True
        else:
            return None, False

    def api_add_label_ip(self, label_j : dict, label_id : str, ips: [str]) -> bool:
        """
        This method will add a list of ips to dynamic_criteria of a label.
        :param label_j: label json
        :param label_id: id of label
        :param ips: ips that we would like to add
        :return:
        """
        headers = {"Authorization": f"Bearer {self.access_token}",
                   'content-type': 'application/json'}

        for ip in ips:
            label_j["dynamic_criteria"] += [{"field": "numeric_ip_addresses", "op": "SUBNET", "isNew": True, "hasValue": True, "hasError": False,
              "argument": ip}]

        resp = requests.put(f"{self.hostname}/api/{self.api_version}/visibility/labels/{label_id}", data=json.dumps(
            label_j
        ),
                             headers=headers, verify=False)
        if resp.status_code < 300:
            return True
        else:
            return False

    def api_rem_label_ip(self, label_j: dict, label_id: str, ips: [str]) -> bool:
        """
        This method will remove a list of ips to dynamic_criteria of a label.
        :param label_j: label json
        :param label_id: id of label
        :param ips: ips that we would like to remove
        :return:
        """
        headers = {"Authorization": f"Bearer {self.access_token}",
                   'content-type': 'application/json'}

        # for every criteria if on the remove list then remove from json
        for criteria in list(label_j["dynamic_criteria"]):
            if criteria.get("field") == "numeric_ip_addresses":
                if criteria["argument"] in ips:
                    label_j["dynamic_criteria"].remove(criteria)

        # push new rule config management
        resp = requests.put(f"{self.hostname}/api/{self.api_version}/visibility/labels/{label_id}", data=json.dumps(
            label_j
        ),
                            headers=headers, verify=False)
        print(resp.content)
        if resp.status_code < 300:
            return True
        else:
            return False

    def api_add_and_rem_label_ip(self, label_j : dict, label_id : str, ips: [str]) -> bool:
        """
        This method will make sure that a label only has the list of supplied ips in dynamic_criteria.

        Meaning if the label has "1.1.1.1/32" and "1.1.1.2/32" and "8.8.8.8/32" is supplied as "ips", both previous ips
            will bre removed from the label and "8.8.8.8/32" added.
            But if ips was supplied as "1.1.1.1/32" only "1.1.1.2/32 would be dropped.

        :param label_j: label json
        :param label_id: id of label
        :param ips: ips that we would like to be in this label
        :return:
        """
        headers = {"Authorization": f"Bearer {self.access_token}",
                   'content-type': 'application/json'}

        for ip in ips:
            label_j["dynamic_criteria"] += [{"field": "numeric_ip_addresses", "op": "SUBNET", "isNew": True, "hasValue": True, "hasError": False,
              "argument": ip}]

        for criteria in list(label_j["dynamic_criteria"]):
            if criteria.get("field") == "numeric_ip_addresses":
                if criteria["argument"] not in ips:
                    label_j["dynamic_criteria"].remove(criteria)


        resp = requests.put(f"{self.hostname}/api/{self.api_version}/visibility/labels/{label_id}", data=json.dumps(
            label_j
        ),
                             headers=headers, verify=False)
        if resp.status_code < 300:
            return True
        else:
            return False

    def api_rem_label(self, key: str, value: str, vm_ids: [str]) -> bool:
        headers = {"Authorization": f"Bearer {self.access_token}",
                   'content-type': 'application/json'}
        resp = requests.post(f"{self.hostname}/api/{self.api_version}/assets/labels/{key}/{value}", data=json.dumps(
            {"delete": True, "vms": vm_ids}),
                             headers=headers, verify=False)
        if resp.status_code < 300:
            return True
        else:
            return False

    def api_list_rules(self) -> [dict]:
        return self._pagination_get(f"{self.hostname}/api/{self.api_version}/visibility/policy/rules",
                                    {"Authorization": f"Bearer {self.access_token}"})


    @staticmethod
    def _pagination_get(endpoint: str, headers: dict, focus_key: str = "objects", limit: int = 0,
                        additional_params: str = "") -> [any]:
        """
        Generic pagination method used for get requests
        :param endpoint: api endpoint to send request to
        :param headers: headers required in request
        :param focus_key: key of resp object to put into list
        :return: list of resp objects
        """
        if additional_params != "":
            resp = requests.get(endpoint + "?" + additional_params,
                                headers=headers, verify=False)
            # print(endpoint+ "?" + additional_params)
        else:
            resp = requests.get(endpoint,
                                headers=headers, verify=False)
        # print(resp.content)
        if resp.status_code != 200:
            raise Exception(f"Unable to page {endpoint} from server.")

        objects = []
        resp_j = resp.json()
        history_len = resp_j["total_count"]

        # scroll pages if we are not able to get all at once
        if resp_j["total_count"] != resp_j["results_in_page"]:
            objects += resp_j[focus_key]

            while len(objects) != history_len:
                if limit != 0 and limit <= len(objects):
                    return objects

                if additional_params == "":
                    resp = requests.get(
                        f"{endpoint}?offset={str(len(objects))}",
                        headers=headers, verify=False)
                else:
                    resp = requests.get(
                        f"{endpoint}?offset={str(len(objects))}&{additional_params}",
                        headers=headers, verify=False)

                resp_j = resp.json()
                objects += resp_j[focus_key]
        else:
            objects += resp_j[focus_key]

        return objects


LABEL_KEY = "IR"        # name of the key name
LABEL_VALUE = "Quarantine"   # name of the key value


if __name__ == '__main__':
    # authenticate with the API using the public IP of the Centra Mgmt and a credential with no 2FA
    mgmt_server = CentraAPI('https://34.68.229.243', 'gc-api', 'GuardiCore123$')
    if not mgmt_server.login_success():
        exit("Unable to log into the server correctly.")

    # try to find a label matching our LABEL_KEY, LABEL_VALUE (IR, Quarantine)
    labelJ = mgmt_server.api_list_labels(LABEL_KEY, LABEL_VALUE)

    # if unable to
    if labelJ is False:
        # create the label
        labelJ, err = mgmt_server.api_add_label(LABEL_KEY, LABEL_VALUE, [])
        # then pull its details
        labelJ = mgmt_server.api_list_labels(LABEL_KEY, LABEL_VALUE)

    labelId = labelJ["id"]

    # individual add example , supply list of CIDR ip ranges to the list sent as the third arg for the add method
    mgmt_server.api_add_label_ip(labelJ, labelId, ["2.7.2.2/32"])

    """
        Label name and value is pulled from LABEL_KEY and LABEL_VALUE variable on like 299 and 300
    
        Adding IPs to a label::
            mgmt_server.api_add_label_ip(labelJ, labelId, ["2.7.2.2/32"])
        Removing IPs from a label ::
            mgmt_server.api_rem_label_ip(labelJ, labelId, ["2.7.2.2/32"])
        Only have the following list of IPs on a label ::
            mgmt_server.api_add_and_rem_label_ip(labelJ, labelId,["1.1.8.5/32"])
    """
