# -*- encoding: utf-8 -*-
'''
Tca Bandit Plugin
'''
import os
import yaml
import json
import subprocess

PWD = os.getcwd()
WOORK_DIR = os.environ.get("RESULT_DIR")
SOURCE_DIR = os.environ.get("SOURCE_DIR")

def decode_str(text) -> str:
    try:
        return text.decode(encoding='UTF-8')
    except UnicodeDecodeError:
        return text.decode(encoding="gbk", errors="surrogateescape")

def get_task_params() -> dict:
    """
    获取需要任务参数
    :return:
    """
    task_request_file = os.environ["TASK_REQUEST"]
    with open(task_request_file, "r") as rf:
        task_request = json.load(rf)
    task_params = task_request["task_params"]
    return task_params

class Bandit():

    def __init__(self, params):
        self.params = params
        self.tool = self._get_tool()

    def _get_tool(self) -> str:
        if os.environ.get("PYTHONPATH"):
            raise Exception("find PYTHONPATH in env!")
        os.environ["PYTHONPATH"] = PWD
        tool_bin_dir = os.path.join(PWD, "bin")
        path = os.environ["PATH"]
        os.environ['PATH'] =  path + os.pathsep + tool_bin_dir
        return os.path.join(tool_bin_dir, "bandit")

    def _get_config(self, rules) -> str:
        custom_config = os.environ.get("BANDIT_CONFIG")
        if custom_config and os.path.exists(os.path.join(SOURCE_DIR, custom_config)):
            return os.path.join(SOURCE_DIR, custom_config)
        tca_config = os.path.join(WOORK_DIR, "tca-bandit.yaml")
        rule_names = list()
        for rule in rules:
            rule_name = rule["name"]
            rule_names.append(rule_name)
        rule_config = dict()
        rule_config["tests"] = rule_names
        with open(tca_config, "a", encoding="utf-8") as fw:
            yaml.dump(rule_config, fw, default_flow_style=False)
        return tca_config

    def analyze(self) -> list:
        print("当前使用的工具：" + self.tool)
        issues = []
        relpos = len(SOURCE_DIR) + 1
        issues_file = os.path.join(WOORK_DIR, "bandit-result.json")
        scan_cmd = ["python3", "-m", "bandit", "-f", "json", "-o", issues_file, "-v"]
        # rules去重
        rule_list = params["rule_list"]
        rule_names = set()
        rules = []
        for r in rule_list:
            if r["name"] not in rule_names:
                rule_names.add(r["name"])
                rules.append(r)
        # 如果未指定配置文件，则使用默认配置
        config_file = self._get_config(rules)
        scan_cmd.extend(["-c", config_file, "-r", SOURCE_DIR])
        print(scan_cmd)
        try:
            sp = subprocess.Popen(scan_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            _, stderr = sp.communicate(timeout=int(os.environ.get("TCA_TASK_TIMEOUT", "600")))
            if stderr:
                stderr_str = decode_str(stderr)
                print(stderr_str)
        except Exception as err:
            print(f"分析过程异常: {err}")
            return issues
        # 分析异常时可能生成空文件导致读取异常
        try:
            with open(issues_file, "r") as fr:
                datas = json.load(fp=fr)
        except Exception as err:
            print(f"解析结果异常: {err}")
            return issues
        results = datas["results"]
        for data in results:
            issue_rule = data["test_id"]
            issue_msg = data["issue_text"]
            issue_file = data["filename"][relpos:]
            issue_line = data["line_number"]
            issue_col = data["col_offset"]
            if data["more_info"]:
                issue_msg = issue_msg + "\n\n" + data["more_info"]
            if "issue_cwe" in data and "id" in data["issue_cwe"] and "link" in data["issue_cwe"]: 
                issue_msg = issue_msg + "\n" + f'[CWE-{data["issue_cwe"]["id"]}]' + data["issue_cwe"]["link"]
            issues.append(
                {
                    "path": issue_file,
                    "rule": issue_rule,
                    "msg": issue_msg,
                    "line": issue_line,
                    "column": issue_col,
                }
            )
        return issues


if __name__ == "__main__":
    params = get_task_params()
    tool = Bandit(params)
    result_file = os.path.join(WOORK_DIR, "result.json")
    issues = tool.analyze()
    with open(result_file, "w") as fw:
        json.dump(issues, fw, indent=2)
