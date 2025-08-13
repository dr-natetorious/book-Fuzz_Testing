#!/usr/bin/env python3
"""
Chapter Processing Script with Transformer Models
Processes book chapters using AI models with iterative improvement and evaluation.
"""

import argparse
import os
import sys
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
import json
import re
from datetime import datetime

try:
    from transformers import AutoTokenizer, AutoModelForCausalLM
    import torch
except ImportError:
    print("Error: transformers and torch are required. Install with:")
    print("pip install transformers torch")
    sys.exit(1)


@dataclass
class Action:
    """Represents a single edit action on the chapter."""
    action_type: str  # ADD or DELETE
    before_marker: Optional[str] = None
    after_marker: Optional[str] = None
    content: Optional[str] = None  # Used by ADD
    
    def __post_init__(self):
        if self.action_type not in ["ADD", "DELETE"]:
            raise ValueError("action_type must be 'ADD' or 'DELETE'")


@dataclass
class ProcessingConfig:
    """Configuration for chapter processing."""
    outline_path: str
    chapter_path: str
    number: int
    instruction_path: str
    model_name: Optional[str] = None
    model: Optional[Any] = None
    tokenizer: Optional[Any] = None
    evaluate: Optional[str] = None
    branch: bool = False
    
    def __post_init__(self):
        if not self.model_name and not self.model:
            raise ValueError("Either model_name or model must be provided")
        if self.model_name and self.model:
            raise ValueError("Provide either model_name or model, not both")


@dataclass
class Evaluation:
    """Results from evaluating a chapter iteration."""
    grade: str
    change_quality: str
    accept: bool
    recommendations: str
    
    def __post_init__(self):
        valid_grades = ['A', 'B', 'C', 'D', 'F']
        if self.grade not in valid_grades or self.change_quality not in valid_grades:
            raise ValueError("Grades must be A, B, C, D, or F")


@dataclass
class RuntimeState:
    """Current state of the chapter processing."""
    number: int
    outline_markdown: str
    chapter_markdown: str
    original_chapter: str
    iteration: int = 0
    
    def get_chapter_backup(self) -> str:
        """Get a backup of the current chapter state."""
        return self.chapter_markdown


class ChapterProcessor:
    """Main class for processing chapters with transformer models."""
    
    def __init__(self, config: ProcessingConfig):
        """Initialize the processor with a configuration object."""
        self.config = config
        self.model_name = config.model_name
        self.tokenizer = config.tokenizer
        self.model = config.model
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        # If model is provided, we assume it's already loaded
        self.model_loaded = config.model is not None and config.tokenizer is not None
        
        # Default format instructions
        self.action_format = """
Output your response as a JSON array of actions. Each action should have:
{
  "action_type": "ADD" or "DELETE",
  "before_marker": "text that comes before the change (optional)",
  "after_marker": "text that comes after the change (optional)", 
  "content": "content to add (for ADD actions only)"
}

Example:
[
  {
    "action_type": "ADD",
    "before_marker": "## Introduction",
    "after_marker": "The main concept",
    "content": "This chapter explores the fundamental principles that will guide our understanding."
  },
  {
    "action_type": "DELETE",
    "before_marker": "outdated information",
    "after_marker": "continues with"
  }
]
"""
        
        self.evaluation_format = """
Output your evaluation as JSON:
{
  "grade": "A-F letter grade for overall chapter quality",
  "change_quality": "A-F letter grade for quality of changes made", 
  "accept": true/false whether changes should be accepted,
  "recommendations": "5-7 sentences about what still needs improvement"
}
"""
        
        self.default_evaluation = """
Evaluate this chapter for:
1. Clarity and readability
2. Logical flow and organization
3. Completeness relative to outline
4. Quality of recent changes
5. Overall coherence with the book structure
"""
    
    def load_model(self):
        """Load the transformer model and tokenizer."""
        if self.model_loaded:
            print("Using pre-loaded model")
            return
            
        if not self.model_name:
            raise ValueError("Either model_name must be provided or model must be pre-loaded")
            
        print(f"Loading model: {self.model_name}")
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                torch_dtype=torch.float16 if self.device.type == "cuda" else torch.float32,
                device_map="auto" if self.device.type == "cuda" else None
            )
            
            # Add pad token if it doesn't exist
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token
                
            self.model_loaded = True
            print(f"Model loaded successfully on {self.device}")
        except Exception as e:
            print(f"Error loading model: {e}")
            sys.exit(1)
    
    def read_file(self, filepath: str) -> str:
        """Read content from a file."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return f.read()
        except FileNotFoundError:
            print(f"Error: File not found: {filepath}")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading file {filepath}: {e}")
            sys.exit(1)
    
    def create_git_branch(self, chapter_number: int):
        """Create a new git branch for this processing session."""
        branch_name = f"chapter-{chapter_number}-processing-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        try:
            subprocess.run(["git", "checkout", "-b", branch_name], check=True, capture_output=True)
            print(f"Created git branch: {branch_name}")
            return branch_name
        except subprocess.CalledProcessError as e:
            print(f"Warning: Could not create git branch: {e}")
            return None
    
    def generate_response(self, prompt: str, max_length: int = 2048) -> str:
        """Generate a response from the model."""
        inputs = self.tokenizer.encode(prompt, return_tensors="pt", truncation=True, max_length=2048)
        inputs = inputs.to(self.device)
        
        with torch.no_grad():
            outputs = self.model.generate(
                inputs,
                max_length=len(inputs[0]) + max_length,
                num_return_sequences=1,
                temperature=0.7,
                do_sample=True,
                pad_token_id=self.tokenizer.pad_token_id,
                eos_token_id=self.tokenizer.eos_token_id
            )
        
        # Decode only the generated part
        generated_text = self.tokenizer.decode(outputs[0][len(inputs[0]):], skip_special_tokens=True)
        return generated_text.strip()
    
    def process(self, state: RuntimeState, instruction: str) -> List[Action]:
        """Process the chapter and return a list of actions."""
        prompt = f"""Task: {instruction}

Outline: <outline>{state.outline_markdown}</outline>

Chapter: <chapter>{state.chapter_markdown}</chapter>

{self.action_format}

Actions:"""
        
        response = self.generate_response(prompt)
        
        # Extract JSON from response
        try:
            # Look for JSON array in the response
            json_match = re.search(r'\[.*?\]', response, re.DOTALL)
            if json_match:
                actions_data = json.loads(json_match.group())
            else:
                # Try to parse the entire response as JSON
                actions_data = json.loads(response)
            
            actions = []
            for action_data in actions_data:
                action = Action(
                    action_type=action_data["action_type"],
                    before_marker=action_data.get("before_marker"),
                    after_marker=action_data.get("after_marker"),
                    content=action_data.get("content")
                )
                actions.append(action)
            
            return actions
        except (json.JSONDecodeError, KeyError) as e:
            print(f"Error parsing actions from model response: {e}")
            print(f"Model response: {response}")
            return []
    
    def apply_actions(self, state: RuntimeState, actions: List[Action]) -> bool:
        """Apply actions to the chapter markdown."""
        if not actions:
            return False
        
        modified = False
        chapter_text = state.chapter_markdown
        
        for action in actions:
            if action.action_type == "ADD":
                if action.before_marker and action.after_marker:
                    # Insert between markers
                    pattern = f"({re.escape(action.before_marker)})(.*?)({re.escape(action.after_marker)})"
                    replacement = f"\\1\\2{action.content}\\3"
                    new_text = re.sub(pattern, replacement, chapter_text, flags=re.DOTALL)
                    if new_text != chapter_text:
                        chapter_text = new_text
                        modified = True
                elif action.before_marker:
                    # Insert after marker
                    pattern = f"({re.escape(action.before_marker)})"
                    replacement = f"\\1{action.content}"
                    new_text = re.sub(pattern, replacement, chapter_text)
                    if new_text != chapter_text:
                        chapter_text = new_text
                        modified = True
                else:
                    # Append to end
                    chapter_text += f"\n{action.content}"
                    modified = True
                    
            elif action.action_type == "DELETE":
                if action.before_marker and action.after_marker:
                    # Delete between markers
                    pattern = f"{re.escape(action.before_marker)}(.*?){re.escape(action.after_marker)}"
                    new_text = re.sub(pattern, f"{action.before_marker}{action.after_marker}", chapter_text, flags=re.DOTALL)
                    if new_text != chapter_text:
                        chapter_text = new_text
                        modified = True
        
        if modified:
            state.chapter_markdown = chapter_text
        
        return modified
    
    def evaluate_iteration(self, state: RuntimeState, evaluation_instruction: str) -> Evaluation:
        """Evaluate the current iteration of the chapter."""
        prompt = f"""Evaluate: {evaluation_instruction}

Original Chapter: <original>{state.original_chapter}</original>

Current Chapter: <current>{state.chapter_markdown}</current>

Outline: <outline>{state.outline_markdown}</outline>

{self.evaluation_format}

Evaluation:"""
        
        response = self.generate_response(prompt)
        
        try:
            # Extract JSON from response
            json_match = re.search(r'\{.*?\}', response, re.DOTALL)
            if json_match:
                eval_data = json.loads(json_match.group())
            else:
                eval_data = json.loads(response)
            
            return Evaluation(
                grade=eval_data["grade"],
                change_quality=eval_data["change_quality"],
                accept=eval_data["accept"],
                recommendations=eval_data["recommendations"]
            )
        except (json.JSONDecodeError, KeyError) as e:
            print(f"Error parsing evaluation: {e}")
            print(f"Model response: {response}")
            # Return a default failing evaluation
            return Evaluation(
                grade="F",
                change_quality="F", 
                accept=False,
                recommendations="Could not evaluate due to parsing error."
            )
    
    def commit_changes(self, state: RuntimeState, evaluation: Evaluation):
        """Commit changes to git if they're good enough."""
        chapter_file = f"Chapters/{state.number}_*.md"  # Will need actual filename
        
        try:
            # Write the updated chapter
            chapter_files = [f for f in os.listdir("Chapters") if f.startswith(f"{state.number}_")]
            if chapter_files:
                chapter_path = os.path.join("Chapters", chapter_files[0])
                with open(chapter_path, 'w', encoding='utf-8') as f:
                    f.write(state.chapter_markdown)
                
                # Git add and commit
                subprocess.run(["git", "add", chapter_path], check=True)
                commit_msg = f"Chapter {state.number} iteration {state.iteration}: Grade {evaluation.grade}, Change Quality {evaluation.change_quality}"
                subprocess.run(["git", "commit", "-m", commit_msg], check=True)
                print(f"Committed changes: {commit_msg}")
        except Exception as e:
            print(f"Warning: Could not commit changes: {e}")
    
    def process_chapter(self, *, instructions: Optional[str] = None, evaluation: Optional[str] = None) -> bool:
        """Main processing loop for a chapter."""
        # Load model
        self.load_model()
        
        # Read files
        outline = self.read_file(self.config.outline_path)
        chapter = self.read_file(self.config.chapter_path)
        
        # Use provided instructions or read from file
        if instructions is not None:
            instruction = instructions
        else:
            instruction = self.read_file(self.config.instruction_path)
        
        # Create initial state
        state = RuntimeState(
            number=self.config.number,
            outline_markdown=outline,
            chapter_markdown=chapter,
            original_chapter=chapter
        )
        
        # Create git branch if requested
        branch = None
        if self.config.branch:
            branch = self.create_git_branch(self.config.number)
        
        # Determine evaluation instruction
        if evaluation is not None:
            eval_instruction = evaluation
        elif self.config.evaluate is not None:
            eval_instruction = self.config.evaluate
        else:
            eval_instruction = self.default_evaluation
        
        max_iterations = 5  # Prevent infinite loops
        best_grade = None  # Start with no grade achieved
        grade_values = {'A': 5, 'B': 4, 'C': 3, 'D': 2, 'F': 1}
        
        print(f"\nStarting processing of Chapter {self.config.number}")
        print(f"Max iterations: {max_iterations}")
        print("-" * 50)
        
        for iteration in range(max_iterations):
            state.iteration = iteration + 1
            print(f"\nIteration {state.iteration}:")
            
            # Process: Get actions from model
            print("  Generating actions...")
            actions = self.process(state, instruction)
            
            if not actions:
                print("  No actions generated, stopping.")
                break
            
            print(f"  Generated {len(actions)} actions")
            
            # Apply actions
            print("  Applying actions...")
            modified = self.apply_actions(state, actions)
            
            if not modified:
                print("  No changes made, stopping.")
                break
            
            # Evaluate
            print("  Evaluating changes...")
            eval_result = self.evaluate_iteration(state, eval_instruction)
            
            print(f"  Grade: {eval_result.grade}")
            print(f"  Change Quality: {eval_result.change_quality}")
            print(f"  Accept: {eval_result.accept}")
            print(f"  Recommendations: {eval_result.recommendations}")
            
            # Commit if accepted
            if eval_result.accept:
                self.commit_changes(state, eval_result)
                # Update best grade if this is better (or first grade)
                if best_grade is None or grade_values[eval_result.grade] > grade_values[best_grade]:
                    best_grade = eval_result.grade
                
                # Stop if we got an A
                if eval_result.grade == 'A':
                    print("  Achieved grade A, stopping.")
                    break
            else:
                # Revert changes
                print("  Changes rejected, reverting...")
                state.chapter_markdown = state.get_chapter_backup()
        
        print(f"\nProcessing complete. Best grade achieved: {best_grade or 'None'}")
        return best_grade is not None and best_grade in ['A', 'B', 'C']  # Success means C or better


def main():
    """Main entry point for command line usage."""
    parser = argparse.ArgumentParser(description="Process book chapters with transformer models")
    parser.add_argument("--model", required=True, help="Model name or path")
    parser.add_argument("--outline", required=True, help="Path to outline.md")
    parser.add_argument("--chapter", required=True, help="Path to chapter markdown file")
    parser.add_argument("--number", type=int, required=True, help="Chapter number")
    parser.add_argument("--instruction", required=True, help="Path to instructions.md")
    parser.add_argument("--branch", action="store_true", help="Create a git branch for this processing session")
    parser.add_argument("--evaluate", help="Custom evaluation instructions")
    
    args = parser.parse_args()
    
    # Create config from args
    config = ProcessingConfig(
        outline_path=args.outline,
        chapter_path=args.chapter,
        number=args.number,
        instruction_path=args.instruction,
        model_name=args.model,
        evaluate=args.evaluate,
        branch=args.branch
    )
    
    # Validate files exist
    for filepath in [config.outline_path, config.chapter_path, config.instruction_path]:
        if not os.path.exists(filepath):
            print(f"Error: File does not exist: {filepath}")
            sys.exit(1)
    
    # Initialize and run processor
    processor = ChapterProcessor(config)
    success = processor.process_chapter()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()