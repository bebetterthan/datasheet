"""
Q&A Generator module for creating instruction-output pairs from content.
Converts raw security content into training data format.
"""

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum


class QuestionType(str, Enum):
    """Types of questions to generate."""
    HOW_TO = "how_to"
    WHAT_IS = "what_is"
    EXPLAIN = "explain"
    DEMONSTRATE = "demonstrate"
    COMPARE = "compare"
    LIST = "list"
    TROUBLESHOOT = "troubleshoot"
    ANALYZE = "analyze"


@dataclass
class QAPair:
    """A question-answer pair."""
    instruction: str
    input_context: str
    output: str
    question_type: QuestionType
    metadata: Dict[str, Any]


class QAGenerator:
    """
    Generates Q&A pairs from security content.
    Creates diverse instruction-output pairs for fine-tuning.
    """
    
    # Templates for different question types
    TEMPLATES = {
        QuestionType.HOW_TO: [
            "How do I {action}?",
            "What are the steps to {action}?",
            "How can I {action}?",
            "Explain how to {action}.",
            "Walk me through {action}.",
            "Show me how to {action}.",
        ],
        QuestionType.WHAT_IS: [
            "What is {topic}?",
            "Define {topic}.",
            "Explain what {topic} is.",
            "What does {topic} mean?",
            "Can you explain {topic}?",
        ],
        QuestionType.EXPLAIN: [
            "Explain {topic}.",
            "Describe {topic}.",
            "Give me an overview of {topic}.",
            "Help me understand {topic}.",
            "What should I know about {topic}?",
        ],
        QuestionType.DEMONSTRATE: [
            "Show me an example of {topic}.",
            "Demonstrate {topic}.",
            "Give me a practical example of {topic}.",
            "Can you provide a demonstration of {topic}?",
            "Show how {topic} works in practice.",
        ],
        QuestionType.LIST: [
            "List the {topic}.",
            "What are the different {topic}?",
            "Name some {topic}.",
            "What {topic} should I know about?",
            "Give me a list of {topic}.",
        ],
        QuestionType.TROUBLESHOOT: [
            "How do I troubleshoot {topic}?",
            "What should I check if {topic}?",
            "How do I debug {topic}?",
            "My {topic} isn't working, what should I do?",
            "Help me fix {topic}.",
        ],
        QuestionType.ANALYZE: [
            "Analyze {topic}.",
            "What can you tell me about {topic}?",
            "Break down {topic}.",
            "Help me analyze {topic}.",
            "What's your analysis of {topic}?",
        ],
    }
    
    # Security-specific instruction prefixes
    SECURITY_PREFIXES = [
        "As a penetration tester,",
        "From a red team perspective,",
        "In a security assessment,",
        "During a pentest,",
        "When conducting security testing,",
        "",  # No prefix
    ]
    
    def __init__(
        self,
        use_llm: bool = False,
        llm_provider: Optional[str] = None,
        llm_api_key: Optional[str] = None,
        temperature: float = 0.7,
    ):
        """
        Initialize Q&A generator.
        
        Args:
            use_llm: Use LLM for enhanced generation
            llm_provider: LLM provider (openai, anthropic)
            llm_api_key: API key for LLM
            temperature: Temperature for LLM generation
        """
        self.use_llm = use_llm
        self.llm_provider = llm_provider
        self.llm_api_key = llm_api_key
        self.temperature = temperature
        self._llm_client = None
    
    def generate_from_content(
        self,
        title: str,
        content: str,
        source: str = "",
        category: str = "",
        code_blocks: Optional[List[Dict]] = None,
    ) -> List[QAPair]:
        """
        Generate Q&A pairs from content.
        
        Args:
            title: Content title/heading
            content: Main content text
            source: Source URL/identifier
            category: Content category
            code_blocks: List of code blocks in content
            
        Returns:
            List of QAPair objects
        """
        qa_pairs = []
        
        # Generate based on title
        if title:
            qa_pairs.extend(self._generate_from_title(title, content, category))
        
        # Generate from headers/sections
        sections = self._split_into_sections(content)
        for section_title, section_content in sections:
            qa_pairs.extend(
                self._generate_from_section(section_title, section_content, category)
            )
        
        # Generate from code blocks
        if code_blocks:
            for block in code_blocks:
                qa_pairs.extend(
                    self._generate_from_code(block, title, category)
                )
        
        # Generate from lists
        lists = self._extract_lists(content)
        for list_items in lists:
            qa_pairs.extend(
                self._generate_from_list(list_items, title, category)
            )
        
        # Add metadata to all pairs
        for pair in qa_pairs:
            pair.metadata['source'] = source
            pair.metadata['category'] = category
        
        return qa_pairs
    
    def _generate_from_title(
        self,
        title: str,
        content: str,
        category: str,
    ) -> List[QAPair]:
        """Generate Q&A pairs based on the title."""
        pairs = []
        
        # Determine question types based on title patterns
        title_lower = title.lower()
        
        # How-to content
        if any(kw in title_lower for kw in ['how to', 'guide', 'tutorial', 'walkthrough']):
            action = self._extract_action(title)
            instruction = f"How do I {action}?"
            pairs.append(QAPair(
                instruction=instruction,
                input_context="",
                output=content,
                question_type=QuestionType.HOW_TO,
                metadata={'title': title}
            ))
        
        # Definition content
        elif any(kw in title_lower for kw in ['what is', 'introduction', 'overview']):
            topic = self._extract_topic(title)
            instruction = f"What is {topic}?"
            pairs.append(QAPair(
                instruction=instruction,
                input_context="",
                output=content,
                question_type=QuestionType.WHAT_IS,
                metadata={'title': title}
            ))
        
        # List content
        elif any(kw in title_lower for kw in ['list', 'types', 'methods', 'techniques']):
            topic = self._extract_topic(title)
            instruction = f"What are the different {topic}?"
            pairs.append(QAPair(
                instruction=instruction,
                input_context="",
                output=content,
                question_type=QuestionType.LIST,
                metadata={'title': title}
            ))
        
        # Default explanation
        else:
            topic = self._clean_topic(title)
            instruction = f"Explain {topic}."
            pairs.append(QAPair(
                instruction=instruction,
                input_context="",
                output=content,
                question_type=QuestionType.EXPLAIN,
                metadata={'title': title}
            ))
        
        return pairs
    
    def _generate_from_section(
        self,
        section_title: str,
        section_content: str,
        category: str,
    ) -> List[QAPair]:
        """Generate Q&A from a content section."""
        pairs = []
        
        if len(section_content.strip()) < 100:  # Skip short sections
            return pairs
        
        topic = self._clean_topic(section_title)
        
        # Create explanation Q&A
        instruction = f"Explain {topic}."
        pairs.append(QAPair(
            instruction=instruction,
            input_context="",
            output=section_content,
            question_type=QuestionType.EXPLAIN,
            metadata={'section': section_title}
        ))
        
        return pairs
    
    def _generate_from_code(
        self,
        code_block: Dict,
        context_title: str,
        category: str,
    ) -> List[QAPair]:
        """Generate Q&A from code blocks."""
        pairs = []
        
        code = code_block.get('code', '')
        language = code_block.get('language', '')
        
        if len(code.strip()) < 20:  # Skip trivial code
            return pairs
        
        # Determine code type and generate appropriate questions
        code_lower = code.lower()
        
        # Command/payload examples
        if any(cmd in code_lower for cmd in ['nmap', 'curl', 'wget', 'nc ', 'bash', 'python', 'msfvenom']):
            topic = self._clean_topic(context_title)
            instruction = f"Show me an example command for {topic}."
            
            output = f"Here's an example:\n\n```{language}\n{code}\n```"
            
            pairs.append(QAPair(
                instruction=instruction,
                input_context="",
                output=output,
                question_type=QuestionType.DEMONSTRATE,
                metadata={'code_type': 'command', 'language': language}
            ))
        
        # Script examples
        elif language in ['python', 'bash', 'powershell', 'ruby', 'php']:
            topic = self._clean_topic(context_title)
            instruction = f"Write a {language} script for {topic}."
            
            output = f"```{language}\n{code}\n```"
            
            pairs.append(QAPair(
                instruction=instruction,
                input_context="",
                output=output,
                question_type=QuestionType.DEMONSTRATE,
                metadata={'code_type': 'script', 'language': language}
            ))
        
        return pairs
    
    def _generate_from_list(
        self,
        list_items: List[str],
        context_title: str,
        category: str,
    ) -> List[QAPair]:
        """Generate Q&A from list content."""
        pairs = []
        
        if len(list_items) < 3:  # Skip short lists
            return pairs
        
        topic = self._clean_topic(context_title)
        instruction = f"List the {topic}."
        
        output = "\n".join(f"- {item}" for item in list_items)
        
        pairs.append(QAPair(
            instruction=instruction,
            input_context="",
            output=output,
            question_type=QuestionType.LIST,
            metadata={'list_count': len(list_items)}
        ))
        
        return pairs
    
    def _split_into_sections(self, content: str) -> List[Tuple[str, str]]:
        """Split content into sections by headers."""
        sections = []
        
        # Match markdown headers
        header_pattern = r'^(#{1,3})\s+(.+?)$'
        lines = content.split('\n')
        
        current_header = ""
        current_content = []
        
        for line in lines:
            match = re.match(header_pattern, line)
            if match:
                # Save previous section
                if current_header and current_content:
                    sections.append((current_header, '\n'.join(current_content)))
                
                current_header = match.group(2)
                current_content = []
            else:
                current_content.append(line)
        
        # Save last section
        if current_header and current_content:
            sections.append((current_header, '\n'.join(current_content)))
        
        return sections
    
    def _extract_lists(self, content: str) -> List[List[str]]:
        """Extract bullet/numbered lists from content."""
        lists = []
        current_list = []
        
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            # Match bullet points or numbered items
            if re.match(r'^[-*•]\s+', line) or re.match(r'^\d+[.)]\s+', line):
                item = re.sub(r'^[-*•\d.)]+\s+', '', line)
                current_list.append(item)
            elif current_list:
                if len(current_list) >= 3:
                    lists.append(current_list)
                current_list = []
        
        # Don't forget the last list
        if len(current_list) >= 3:
            lists.append(current_list)
        
        return lists
    
    def _extract_action(self, title: str) -> str:
        """Extract action from how-to title."""
        # Remove common prefixes
        title = re.sub(r'^(how to|guide to|tutorial:?)\s*', '', title, flags=re.I)
        return title.lower().strip()
    
    def _extract_topic(self, title: str) -> str:
        """Extract topic from title."""
        # Remove common prefixes
        title = re.sub(r'^(what is|introduction to|overview of)\s*', '', title, flags=re.I)
        return title.strip()
    
    def _clean_topic(self, title: str) -> str:
        """Clean and normalize topic string."""
        # Remove special characters
        title = re.sub(r'[#*_`]', '', title)
        # Remove trailing punctuation
        title = re.sub(r'[:.!?]+$', '', title)
        return title.strip()
    
    def convert_to_alpaca(
        self,
        qa_pairs: List[QAPair],
        source: str = "",
        difficulty: str = "intermediate",
    ) -> List[Dict[str, Any]]:
        """
        Convert QAPairs to Alpaca format.
        
        Args:
            qa_pairs: List of QAPair objects
            source: Source identifier
            difficulty: Difficulty level
            
        Returns:
            List of Alpaca format dictionaries
        """
        samples = []
        
        for pair in qa_pairs:
            sample = {
                'instruction': pair.instruction,
                'input': pair.input_context,
                'output': pair.output,
                'category': pair.metadata.get('category', ''),
                'source': pair.metadata.get('source', source),
                'difficulty': difficulty,
                'tags': self._generate_tags(pair),
            }
            samples.append(sample)
        
        return samples
    
    def _generate_tags(self, pair: QAPair) -> List[str]:
        """Generate tags for a Q&A pair."""
        tags = [pair.question_type.value]
        
        # Add language tag if present
        language = pair.metadata.get('language')
        if language:
            tags.append(language)
        
        # Add code type if present
        code_type = pair.metadata.get('code_type')
        if code_type:
            tags.append(code_type)
        
        return tags


class LLMQAGenerator(QAGenerator):
    """Q&A Generator with LLM enhancement."""
    
    SYSTEM_PROMPT = """You are a cybersecurity expert creating training data for a red team AI assistant.
Generate high-quality question-answer pairs from the provided security content.
Ensure questions are practical and answers are technically accurate.
Focus on offensive security, penetration testing, and red team operations."""
    
    def _init_llm_client(self):
        """Initialize LLM client."""
        if self._llm_client is not None:
            return
        
        if self.llm_provider == "openai":
            try:
                from openai import OpenAI
                self._llm_client = OpenAI(api_key=self.llm_api_key)
            except ImportError:
                raise ImportError("openai package required for LLM generation")
        
        elif self.llm_provider == "anthropic":
            try:
                from anthropic import Anthropic
                self._llm_client = Anthropic(api_key=self.llm_api_key)
            except ImportError:
                raise ImportError("anthropic package required for LLM generation")
    
    async def enhance_qa_pair(
        self,
        pair: QAPair,
    ) -> QAPair:
        """Enhance a Q&A pair using LLM."""
        if not self.use_llm:
            return pair
        
        self._init_llm_client()
        
        prompt = f"""Improve this Q&A pair for training a security AI:

Question: {pair.instruction}
Context: {pair.input_context}
Answer: {pair.output}

Generate an improved version with:
1. A clearer, more specific question
2. A comprehensive, technically accurate answer
3. Include practical examples where appropriate

Respond in JSON format:
{{"instruction": "...", "input": "...", "output": "..."}}"""
        
        try:
            if self.llm_provider == "openai":
                response = self._llm_client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": self.SYSTEM_PROMPT},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=self.temperature,
                )
                content = response.choices[0].message.content
            
            elif self.llm_provider == "anthropic":
                response = self._llm_client.messages.create(
                    model="claude-3-haiku-20240307",
                    max_tokens=2000,
                    system=self.SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": prompt}],
                )
                content = response.content[0].text
            
            # Parse response
            import json
            enhanced = json.loads(content)
            
            return QAPair(
                instruction=enhanced.get('instruction', pair.instruction),
                input_context=enhanced.get('input', pair.input_context),
                output=enhanced.get('output', pair.output),
                question_type=pair.question_type,
                metadata=pair.metadata,
            )
        
        except Exception as e:
            # Return original on error
            return pair
