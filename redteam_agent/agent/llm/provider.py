"""
LLM Provider Module
===================

Interface to the fine-tuned LLM for the Red Team Agent.
Supports multiple backends:
- Local models (transformers + PEFT)
- OpenAI-compatible APIs (vLLM, Ollama, LM Studio)
- Cloud APIs (OpenAI, Anthropic)
"""

from typing import Dict, Any, Optional, List, Union
from pathlib import Path
from abc import ABC, abstractmethod
import os
import json

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

from agent.utils.logger import get_logger
from agent.utils.config import Config


class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers."""
    
    def __init__(self, config: Optional[Config] = None):
        self.logger = get_logger(self.__class__.__name__)
        self.config = config or Config()
        self._healthy = False
    
    @abstractmethod
    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        stop_sequences: Optional[List[str]] = None
    ) -> str:
        """Generate response from the model."""
        pass
    
    @abstractmethod
    def chat(
        self,
        messages: List[Dict[str, str]],
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None
    ) -> str:
        """Chat-style generation with message history."""
        pass
    
    @abstractmethod
    def is_healthy(self) -> bool:
        """Check if provider is healthy and ready."""
        pass
    
    def get_info(self) -> Dict[str, Any]:
        """Get provider information."""
        return {
            "provider_type": self.__class__.__name__,
            "healthy": self.is_healthy()
        }


class LocalLLMProvider(BaseLLMProvider):
    """
    Local LLM Provider using transformers + PEFT.
    
    Loads fine-tuned model locally with GPU acceleration.
    """
class LocalLLMProvider(BaseLLMProvider):
    """
    Local LLM Provider using transformers + PEFT.
    
    Loads fine-tuned model locally with GPU acceleration.
    """
    
    def __init__(
        self,
        config: Optional[Config] = None,
        model_path: Optional[str] = None,
        base_model: Optional[str] = None
    ):
        """
        Initialize Local LLM Provider.
        
        Args:
            config: Configuration object
            model_path: Path to fine-tuned model (overrides config)
            base_model: Base model name (overrides config)
        """
        super().__init__(config)
        
        if not TORCH_AVAILABLE:
            raise ImportError("torch is required for LocalLLMProvider. Install with: pip install torch transformers peft")
        
        # Model settings
        self.model_path = model_path or self.config.get(
            "llm.model_path",
            "~/redteam-ai-agent/outputs/run_20251130_084846/final_model"
        )
        self.base_model = base_model or self.config.get(
            "llm.base_model",
            "Qwen/Qwen2.5-Coder-7B-Instruct"
        )
        
        # Generation settings
        self.max_tokens = self.config.get("llm.max_tokens", 2048)
        self.temperature = self.config.get("llm.temperature", 0.3)
        self.top_p = self.config.get("llm.top_p", 0.9)
        
        # Model and tokenizer (lazy loaded)
        self._model = None
        self._tokenizer = None
        self._loaded = False
        
    def load(self) -> None:
        """Load the model and tokenizer."""
        if self._loaded:
            return
            
        self.logger.info(f"Loading model from {self.model_path}")
        
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer
            from peft import PeftModel
            
            # Expand paths
            model_path = Path(self.model_path).expanduser()
            
            # Load tokenizer from base model
            self.logger.info(f"Loading tokenizer from {self.base_model}")
            self._tokenizer = AutoTokenizer.from_pretrained(
                self.base_model,
                trust_remote_code=True
            )
            
            # Ensure pad token
            if self._tokenizer.pad_token is None:
                self._tokenizer.pad_token = self._tokenizer.eos_token
                
            # Load base model
            self.logger.info(f"Loading base model: {self.base_model}")
            base_model = AutoModelForCausalLM.from_pretrained(
                self.base_model,
                torch_dtype=torch.float16,
                device_map="auto",
                trust_remote_code=True
            )
            
            # Load LoRA adapter
            self.logger.info(f"Loading LoRA adapter from {model_path}")
            self._model = PeftModel.from_pretrained(
                base_model,
                str(model_path)
            )
            
            # Set to eval mode
            self._model.eval()
            
            self._loaded = True
            self.logger.info("Model loaded successfully!")
            
        except Exception as e:
            self.logger.error(f"Failed to load model: {e}")
            raise
            
    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        stop_sequences: Optional[List[str]] = None
    ) -> str:
        """
        Generate response from the model.
        
        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            stop_sequences: Sequences that stop generation
            
        Returns:
            Generated response text
        """
        # Ensure model is loaded
        if not self._loaded:
            self.load()
            
        # Build full prompt
        full_prompt = self._build_prompt(prompt, system_prompt)
        
        # Tokenize
        inputs = self._tokenizer(
            full_prompt,
            return_tensors="pt",
            truncation=True,
            max_length=4096
        ).to(self._model.device)
        
        # Generate
        with torch.no_grad():
            outputs = self._model.generate(
                **inputs,
                max_new_tokens=max_tokens or self.max_tokens,
                temperature=temperature or self.temperature,
                top_p=self.top_p,
                do_sample=True,
                pad_token_id=self._tokenizer.pad_token_id,
                eos_token_id=self._tokenizer.eos_token_id
            )
            
        # Decode response
        response = self._tokenizer.decode(
            outputs[0][inputs["input_ids"].shape[1]:],
            skip_special_tokens=True
        )
        
        # Apply stop sequences
        if stop_sequences:
            for stop in stop_sequences:
                if stop in response:
                    response = response.split(stop)[0]
                    
        return response.strip()
        
    def _build_prompt(
        self,
        prompt: str,
        system_prompt: Optional[str] = None
    ) -> str:
        """Build the full prompt with system and user messages."""
        # Use Qwen chat template
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
            
        messages.append({"role": "user", "content": prompt})
        
        # Apply chat template
        try:
            return self._tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True
            )
        except:
            # Fallback format
            parts = []
            if system_prompt:
                parts.append(f"System: {system_prompt}\n")
            parts.append(f"User: {prompt}\n")
            parts.append("Assistant:")
            return "".join(parts)
            
    def chat(
        self,
        messages: List[Dict[str, str]],
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None
    ) -> str:
        """
        Chat-style generation with message history.
        
        Args:
            messages: List of {"role": "...", "content": "..."} messages
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            
        Returns:
            Generated response text
        """
        if not self._loaded:
            self.load()
            
        # Apply chat template
        try:
            prompt = self._tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True
            )
        except:
            # Fallback
            parts = []
            for msg in messages:
                role = msg.get("role", "user").capitalize()
                content = msg.get("content", "")
                parts.append(f"{role}: {content}\n")
            parts.append("Assistant:")
            prompt = "".join(parts)
            
        # Generate
        inputs = self._tokenizer(
            prompt,
            return_tensors="pt",
            truncation=True,
            max_length=4096
        ).to(self._model.device)
        
        with torch.no_grad():
            outputs = self._model.generate(
                **inputs,
                max_new_tokens=max_tokens or self.max_tokens,
                temperature=temperature or self.temperature,
                top_p=self.top_p,
                do_sample=True,
                pad_token_id=self._tokenizer.pad_token_id,
                eos_token_id=self._tokenizer.eos_token_id
            )
            
        response = self._tokenizer.decode(
            outputs[0][inputs["input_ids"].shape[1]:],
            skip_special_tokens=True
        )
        
        return response.strip()
        
    def get_embeddings(self, text: str):
        """
        Get text embeddings (for similarity search).
        
        Args:
            text: Text to embed
            
        Returns:
            Embedding tensor
        """
        if not self._loaded:
            self.load()
            
        inputs = self._tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=512
        ).to(self._model.device)
        
        with torch.no_grad():
            outputs = self._model.model(**inputs, output_hidden_states=True)
            # Use last hidden state mean pooling
            embeddings = outputs.hidden_states[-1].mean(dim=1)
            
        return embeddings
    
    def is_healthy(self) -> bool:
        """Check if model is loaded and healthy."""
        return self._loaded and self._model is not None
        
    def unload(self) -> None:
        """Unload model to free memory."""
        if self._model is not None:
            del self._model
            self._model = None
        if self._tokenizer is not None:
            del self._tokenizer
            self._tokenizer = None
        self._loaded = False
        
        # Clear CUDA cache
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
            
        self.logger.info("Model unloaded")
        
    @property
    def is_loaded(self) -> bool:
        """Check if model is loaded."""
        return self._loaded
    
    def get_info(self) -> Dict[str, Any]:
        """Get provider information."""
        info = super().get_info()
        info.update({
            "model_path": self.model_path,
            "base_model": self.base_model,
            "loaded": self._loaded,
            "device": str(self._model.device) if self._model else None
        })
        return info
        
    def __del__(self):
        """Cleanup on deletion."""
        self.unload()


class APILLMProvider(BaseLLMProvider):
    """
    API-based LLM Provider.
    
    Supports OpenAI-compatible APIs (vLLM, Ollama, LM Studio, etc.)
    """
    
    def __init__(
        self,
        config: Optional[Config] = None,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        model_name: Optional[str] = None
    ):
        """
        Initialize API LLM Provider.
        
        Args:
            config: Configuration object
            api_url: API base URL (e.g., http://localhost:8000/v1)
            api_key: API key (if required)
            model_name: Model name to use
        """
        super().__init__(config)
        
        self.api_url = api_url or self.config.get("llm.api_url", "http://localhost:8000/v1")
        self.api_key = api_key or self.config.get("llm.api_key") or os.getenv("REDTEAM_API_KEY")
        self.model_name = model_name or self.config.get("llm.model_name", "redteam-v1")
        
        # Generation settings
        self.max_tokens = self.config.get("llm.max_tokens", 4096)
        self.temperature = self.config.get("llm.temperature", 0.7)
        self.timeout = self.config.get("llm.timeout", 60)
        
        # Test connection
        self._test_connection()
    
    def _test_connection(self) -> None:
        """Test API connection."""
        try:
            import requests
            
            # Try to get models endpoint
            url = f"{self.api_url.rstrip('/')}/models"
            headers = {}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                self._healthy = True
                self.logger.info(f"✓ API connection successful: {self.api_url}")
            else:
                self.logger.warning(f"API returned status {response.status_code}")
                self._healthy = False
        except Exception as e:
            self.logger.warning(f"Could not connect to API: {e}")
            self._healthy = False
    
    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        stop_sequences: Optional[List[str]] = None
    ) -> str:
        """Generate response from the API."""
        import requests
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        return self.chat(messages, max_tokens, temperature)
    
    def chat(
        self,
        messages: List[Dict[str, str]],
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None
    ) -> str:
        """Chat-style generation via API."""
        import requests
        
        url = f"{self.api_url.rstrip('/')}/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        payload = {
            "model": self.model_name,
            "messages": messages,
            "max_tokens": max_tokens or self.max_tokens,
            "temperature": temperature or self.temperature
        }
        
        try:
            response = requests.post(
                url,
                headers=headers,
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            return data["choices"][0]["message"]["content"]
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"API request failed: {e}")
            raise RuntimeError(f"Failed to generate response: {e}")
    
    def is_healthy(self) -> bool:
        """Check if API is healthy."""
        return self._healthy
    
    def get_info(self) -> Dict[str, Any]:
        """Get provider information."""
        info = super().get_info()
        info.update({
            "api_url": self.api_url,
            "model_name": self.model_name,
            "has_api_key": bool(self.api_key)
        })
        return info


class OpenAIProvider(BaseLLMProvider):
    """
    OpenAI API Provider.
    
    For using OpenAI's GPT models (GPT-4, GPT-3.5, etc.)
    """
    
    def __init__(
        self,
        config: Optional[Config] = None,
        api_key: Optional[str] = None,
        model_name: Optional[str] = None
    ):
        """
        Initialize OpenAI Provider.
        
        Args:
            config: Configuration object
            api_key: OpenAI API key
            model_name: Model name (e.g., gpt-4, gpt-3.5-turbo)
        """
        super().__init__(config)
        
        self.api_key = api_key or self.config.get("llm.openai_api_key") or os.getenv("OPENAI_API_KEY")
        self.model_name = model_name or self.config.get("llm.model_name", "gpt-4")
        
        if not self.api_key:
            raise ValueError("OpenAI API key is required. Set via config or OPENAI_API_KEY env var")
        
        # Generation settings
        self.max_tokens = self.config.get("llm.max_tokens", 4096)
        self.temperature = self.config.get("llm.temperature", 0.7)
        self.timeout = self.config.get("llm.timeout", 60)
        
        self._test_connection()
    
    def _test_connection(self) -> None:
        """Test OpenAI API connection."""
        try:
            import requests
            
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            response = requests.get(
                "https://api.openai.com/v1/models",
                headers=headers,
                timeout=5
            )
            
            if response.status_code == 200:
                self._healthy = True
                self.logger.info("✓ OpenAI API connection successful")
            else:
                self.logger.warning(f"OpenAI API returned status {response.status_code}")
                self._healthy = False
        except Exception as e:
            self.logger.warning(f"Could not connect to OpenAI API: {e}")
            self._healthy = False
    
    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        stop_sequences: Optional[List[str]] = None
    ) -> str:
        """Generate response from OpenAI."""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        return self.chat(messages, max_tokens, temperature)
    
    def chat(
        self,
        messages: List[Dict[str, str]],
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None
    ) -> str:
        """Chat-style generation via OpenAI."""
        import requests
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": self.model_name,
            "messages": messages,
            "max_tokens": max_tokens or self.max_tokens,
            "temperature": temperature or self.temperature
        }
        
        try:
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            return data["choices"][0]["message"]["content"]
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"OpenAI API request failed: {e}")
            raise RuntimeError(f"Failed to generate response: {e}")
    
    def is_healthy(self) -> bool:
        """Check if OpenAI API is healthy."""
        return self._healthy
    
    def get_info(self) -> Dict[str, Any]:
        """Get provider information."""
        info = super().get_info()
        info.update({
            "model_name": self.model_name,
            "provider": "OpenAI"
        })
        return info


def create_llm_provider(config: Optional[Config] = None) -> BaseLLMProvider:
    """
    Factory function to create LLM provider based on configuration.
    
    Args:
        config: Configuration object
        
    Returns:
        Appropriate LLM provider instance
        
    Raises:
        ValueError: If provider type is not supported
    """
    config = config or Config()
    provider_type = config.get("llm.provider", "local")
    
    logger = get_logger("LLMFactory")
    logger.info(f"Creating LLM provider: {provider_type}")
    
    if provider_type == "local":
        return LocalLLMProvider(config)
    elif provider_type == "api":
        return APILLMProvider(config)
    elif provider_type == "openai":
        return OpenAIProvider(config)
    else:
        raise ValueError(f"Unsupported provider type: {provider_type}. Use: local, api, or openai")


# Legacy alias for backward compatibility
LLMProvider = LocalLLMProvider
