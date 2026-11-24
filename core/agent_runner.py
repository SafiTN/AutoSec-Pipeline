import os
import sys
import requests
import json

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.config_loader import load_settings


class AgentRunner:
    def __init__(self, settings=None):
        """مشغل الوكيل الأمني المرتبط بنماذج Ollama المحلية"""
        self.settings = settings or load_settings()
        ai_cfg = (
                self.settings.get("ai")
                or self.settings.get("ollama")
                or {
                    "base_url": "http://localhost:11434",
                    "model": "qwen2.5-coder:7b",
                    "timeout_sec": 120,
                    "temperature": 0.2,
                }
        )

        self.provider = ai_cfg.get("provider", "ollama")
        self.model_name = ai_cfg.get("local_model", "qwen2.5-coder:7b")
        self.temperature = ai_cfg.get("temperature", 0.1)

        # عنوان الاتصال الافتراضي مع Ollama محلياً
        self.ollama_url = "http://localhost:11434/api/generate"

    def query_local_agent(self, prompt: str, system_prompt: str = "") -> str:
        """إرسال طلب إلى نموذج الذكاء الاصطناعي المحلي واستقبال الرد البرمجي أو التحليلي"""
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "system": system_prompt,
            "stream": False,
            "options": {
                "temperature": self.temperature
            }
        }

        try:
            print(f"[AgentRunner] Connecting to local Ollama model ({self.model_name})...")
            response = requests.post(self.ollama_url, json=payload, timeout=300)

            if response.status_code == 200:
                result = response.json()
                return result.get("response", "Error: Empty response from model.")
            else:
                return f"Error: Ollama returned status code {response.status_code}"

        except requests.exceptions.ConnectionError:
            return "Error: Could not connect to Ollama. Make sure Ollama is running locally ('ollama serve')."
        except Exception as e:
            return f"Error: {str(e)}"


if __name__ == "__main__":
    # اختبار سريع للوكيل المحلي
    runner = AgentRunner()
    test_prompt = "Write a short Python function to check for open ports."
    sys_prompt = "You are a professional cybersecurity automation assistant."

    print(f"Testing local agent with model: {runner.model_name}")
    output = runner.query_local_agent(test_prompt, sys_prompt)
    print("\n--- Model Response ---")
    print(output)