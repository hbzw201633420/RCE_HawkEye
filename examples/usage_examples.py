"""
使用示例
"""

import asyncio
from rce_scanner import Scanner, Reporter
from rce_scanner.scanner import ScanTarget
from rce_scanner.payload_generator import PayloadGenerator, PayloadType, OSType


async def basic_scan_example():
    """基本扫描示例"""
    print("=== 基本扫描示例 ===")
    
    scanner = Scanner(
        timeout=10,
        max_concurrent=5,
        delay_threshold=4.0
    )
    
    target = ScanTarget(
        url="http://example.com/api?cmd=test",
        method="GET"
    )
    
    results = await scanner.scan([target])
    
    for result in results:
        print(f"目标: {result.target}")
        print(f"发现漏洞: {len(result.vulnerabilities)} 个")
        
        for vuln in result.vulnerabilities:
            print(f"  - [{vuln.severity.value}] {vuln.parameter}: {vuln.description}")


async def post_scan_example():
    """POST请求扫描示例"""
    print("\n=== POST请求扫描示例 ===")
    
    scanner = Scanner(timeout=10, max_concurrent=5)
    
    target = ScanTarget(
        url="http://example.com/api/exec",
        method="POST",
        data={"command": "test", "arg": "value"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    
    results = await scanner.scan([target])
    
    print(f"扫描完成，发现 {sum(len(r.vulnerabilities) for r in results)} 个漏洞")


async def custom_payload_example():
    """自定义Payload示例"""
    print("\n=== 自定义Payload示例 ===")
    
    generator = PayloadGenerator()
    
    generator.add_custom_payload(
        content="; cat /etc/passwd;",
        payload_type=PayloadType.ECHO_BASED,
        os_type=OSType.UNIX,
        description="读取passwd文件",
        expected_output="root:"
    )
    
    generator.add_custom_payload(
        content="& type C:\\Windows\\win.ini",
        payload_type=PayloadType.ECHO_BASED,
        os_type=OSType.WINDOWS,
        description="读取Windows配置文件",
        expected_output="[fonts]"
    )
    
    payloads = generator.get_all_payloads()
    print(f"总共有 {len(payloads)} 个payload")
    
    time_payloads = generator.get_time_based_payloads()
    print(f"时间盲注payload: {len(time_payloads)} 个")


async def report_example():
    """报告生成示例"""
    print("\n=== 报告生成示例 ===")
    
    from rce_scanner.detector import Vulnerability, Severity
    
    vulnerabilities = [
        Vulnerability(
            target="http://example.com/api?cmd=test",
            parameter="cmd",
            payload="; sleep 5;",
            payload_type="time_based",
            severity=Severity.HIGH,
            description="Unix时间盲注漏洞",
            evidence="响应延迟5秒",
            exploitation="通过sleep命令造成延迟",
            remediation="对输入进行严格过滤"
        )
    ]
    
    reporter = Reporter(output_dir="./reports")
    
    json_report = reporter.generate_json_report(vulnerabilities)
    print("JSON报告片段:")
    print(json_report[:200] + "...")
    
    md_report = reporter.generate_markdown_report(vulnerabilities)
    print("\nMarkdown报告片段:")
    print(md_report[:300] + "...")
    
    files = reporter.export_all_formats(vulnerabilities)
    print(f"\n报告已保存:")
    for fmt, filepath in files.items():
        print(f"  - {fmt}: {filepath}")


async def progress_callback_example():
    """进度回调示例"""
    print("\n=== 进度回调示例 ===")
    
    def on_progress(current: int, total: int, target: str):
        print(f"\r扫描进度: {current}/{total} - {target[:50]}", end="")
    
    scanner = Scanner(timeout=5, max_concurrent=3)
    scanner.set_progress_callback(on_progress)
    
    targets = [
        ScanTarget(url="http://example.com/api?cmd=test1"),
        ScanTarget(url="http://example.com/api?cmd=test2"),
        ScanTarget(url="http://example.com/api?cmd=test3"),
    ]
    
    results = await scanner.scan(targets)
    print(f"\n扫描完成，共扫描 {len(results)} 个目标")


async def main():
    """主函数"""
    print("RCE Scanner 使用示例\n")
    
    await basic_scan_example()
    await post_scan_example()
    await custom_payload_example()
    await report_example()
    await progress_callback_example()
    
    print("\n所有示例运行完成!")


if __name__ == "__main__":
    asyncio.run(main())
