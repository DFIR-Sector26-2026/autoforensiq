import subprocess
import os
from src.utils.audit_log import log_action

class BaseWrapper:
    def __init__(self, tool_name: str):
        self.tool_name = tool_name

    def run_command(self, command: list, input_files: list = [],
                    output_files: list = [], timeout: int = 300) -> tuple:
        """
        Runs a shell command.
        Returns (stdout, stderr, returncode).
        Logs to audit log automatically.
        """
        print(f"  [RUNNING] {' '.join(command)}")
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            status = "success" if result.returncode == 0 else "failed"
            log_action(
                tool_name=self.tool_name,
                command=command,
                input_files=input_files,
                output_files=output_files,
                status=status,
                error=result.stderr[:500] if result.stderr else ""
            )
            return result.stdout, result.stderr, result.returncode

        except subprocess.TimeoutExpired:
            log_action(self.tool_name, command, input_files, output_files, "timeout")
            print(f"  [TIMEOUT] {self.tool_name} exceeded {timeout}s")
            return "", "timeout", -1

        except Exception as e:
            log_action(self.tool_name, command, input_files, output_files, "error", str(e))
            print(f"  [ERROR] {self.tool_name}: {e}")
            return "", str(e), -1

    def make_evidence_item(self, artifact_id: str, evidence_type: str,
                           value: str, severity: str = "medium",
                           confidence: float = 0.7,
                           timestamp: str = "",
                           linked_artifacts: list = []) -> dict:
        """
        Returns a dict matching the agreed evidence_item schema exactly.
        Every wrapper uses this to produce output.
        """
        return {
            "artifact_id": artifact_id,
            "source_tool": self.tool_name,
            "evidence_type": evidence_type,
            "timestamp": timestamp,
            "value": value,
            "severity": severity,
            "confidence": confidence,
            "linked_artifacts": linked_artifacts
        }
