import os
import json
import argparse
import requests

def post_comment(pr_number, report_content):
    # 1. 获取 GitHub Actions 自动提供的环境变量
    token = os.getenv("GITHUB_TOKEN")
    repo = os.getenv("GITHUB_REPOSITORY")  # 格式为 "owner/repo"
    
    if not token or not repo:
        print("错误：未找到 GITHUB_TOKEN 或 GITHUB_REPOSITORY 环境变量")
        return

    # 2. 构造 GitHub API URL
    # PR 在 API 层面也被视为一种 Issue
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    
    # 3. 美化内容：将 JSON 包装在 Markdown 代码块中，方便查看
    comment_body = (
        "### 🛡️ SAST 扫描初步报告 (Placeholder)\n"
        "AI Agent 正在集成中... 以下是开源工具生成的原始数据：\n\n"
        f"```json\n{report_content}\n```"
    )

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    # 4. 发送请求
    response = requests.post(url, json={"body": comment_body}, headers=headers)
    
    if response.status_code == 201:
        print("评论发表成功！")
    else:
        print(f"评论发表失败：{response.status_code}, {response.text}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--pr_number", type=int, required=True, help="Pull Request Number")
    parser.add_argument("--report_file", type=str, default="report.json", help="SAST Report File")
    args = parser.parse_args()

    try:
        with open(args.report_file, "r", encoding="utf-8") as f:
            content = f.read()
            # 如果内容太长，GitHub API 会报错，这里简单截断前 3000 字符（仅作为占位展示）
            if len(content) > 3000:
                content = content[:3000] + "\n...内容过长已截断..."
            
        post_comment(args.pr_number, content)
    except FileNotFoundError:
        print(f"找不到文件：{args.report_file}")