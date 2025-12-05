"""
LLM Provider Module
===================

Interface to the fine-tuned LLM for the Red Team Agent.
"""

from typing import Dict, Any, Optional, List
from pathlib import Path
import torch

from agent.utils.logger import get_logger
from agent.utils.config import Config


class LLMProvider:
    """
    LLM Provider for the Red Team Agent.
    
    Handles loading and inference with the fine-tuned Qwen model.
    Supports both local model and API-based inference.
    
    Usage:
        provider = LLMProvider(config)
        response = provider.generate("Analyze this target...")
    """
    
    def __init__(
        self,
        config: Optional[Config] = None,
        model_path: Optional[str] = None,
        base_model: Optional[str] = None
    ):
        """
        Initialize LLM Provider.
        
        Args:
            config: Configuration object
            model_path: Path to fine-tuned model (overrides config)
            base_model: Base model name (overrides config)
        """
        self.logger = get_logger("LLMProvider")
        self.config = config or Config()
        
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
        
    def get_embeddings(self, text: str) -> torch.Tensor:
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
        
    def __del__(self):
        """Cleanup on deletion."""
        self.unload()
