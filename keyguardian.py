#  ML Key Validation using DeBERTa
# NOTE: This file requires additional dependencies:
# pip install onnxruntime numpy tokenizers transformers torch scikit-learn pandas optuna

import json
import os
import re
from typing import Optional

# Dependency checking and graceful failure
ML_DEPS_AVAILABLE = False
try:
    import numpy as np
    import pandas as pd
    import onnxruntime
    import torch
    from sklearn.model_selection import train_test_split, StratifiedKFold
    from sklearn.metrics import accuracy_score, f1_score, classification_report, confusion_matrix
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
        Trainer,
        TrainingArguments,
        EarlyStoppingCallback,
    )
    from torch.utils.data import Dataset
    from onnx.quantization import quantize_dynamic, QuantType
    import optuna
    ML_DEPS_AVAILABLE = True
except ImportError as e:
    print("Warning: One or more ML dependencies not found. KeyGuardian will be disabled.")
    print(f"  > The specific error was: {e}")
    print("  > Please ensure all of the following are installed in your active Python environment:")
    print("  > pip install onnxruntime numpy tokenizers transformers torch scikit-learn pandas optuna")
    # Set all to None to ensure KeyGuardian class fails gracefully
    onnxruntime = np = pd = torch = optuna = None

# --- Constants ---
MODEL_INPUT_NAMES = ['input_ids', 'attention_mask']
MODEL_NAME = "microsoft/deberta-v3-xsmall"
VOCAB_FILE = "vocab.txt" # Standard name, but DeBERTa uses sentencepiece.model
MAX_LENGTH = 128

class KeyGuardian:
    """
    A class to load a quantized DeBERTa ONNX model and perform inference
    to classify if a key candidate is a true positive.
    """
    def __init__(self, model_path: str = "keyguardian.onnx", vocab_path: str = "."):
        self.session: Optional[onnxruntime.InferenceSession] = None
        self.tokenizer: Optional[AutoTokenizer] = None

        if not ML_DEPS_AVAILABLE or onnxruntime is None:
            # The warning has already been printed at import time.
            return

        model_file = os.path.join(vocab_path, model_path)
        
        if not os.path.exists(model_file):
            print(f"Warning: Model file not found at '{model_file}'. ML filtering is disabled.")
            print("You can train a model by running: python keyguardian.py --train")
            return
        
        try:
            # DeBERTa tokenizer is special, load from pretrained
            self.tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
        except Exception as e:
            print(f"Could not load tokenizer for {MODEL_NAME}: {e}. ML filtering disabled.")
            return

        try:
            self.session = onnxruntime.InferenceSession(model_file)
            print(f"KeyGuardian ML model loaded successfully from '{model_file}'.")
        except Exception as e:
            print(f"Error loading ONNX model: {e}")
            self.session = None

    def _preprocess(self, key_candidate: str, code_fragment: str) -> Optional[dict]:
        """Prepares the input text for the DeBERTa model."""
        if not self.tokenizer:
            return None
        
        # Normalize context for better generalization
        context = re.sub(r'[\'"]', '', code_fragment.lower())
        key_len = len(key_candidate)
        
        # Structured input for the model
        text_for_model = f"[KEY] {key_candidate} [CONTEXT] key_len:{key_len} {context}"
        
        encoding = self.tokenizer(
            text_for_model, 
            max_length=MAX_LENGTH, 
            truncation=True, 
            padding="max_length",
            return_tensors="np"
        )
        
        return {
            'input_ids': encoding['input_ids'].astype(np.int64),
            'attention_mask': encoding['attention_mask'].astype(np.int64)
        }

    def predict(self, key_candidate: str, code_fragment: str) -> float:
        """
        Runs inference on the provided key and code context.
        Returns a confidence score (0.0 to 1.0) for being a valid key.
        """
        if not self.session or not self.tokenizer:
            return 0.5 

        model_inputs = self._preprocess(key_candidate, code_fragment)
        if not model_inputs:
            return 0.0

        try:
            outputs = self.session.run(None, model_inputs)
            logits = outputs[0]
            # Apply softmax to convert logits to probabilities
            probs = np.exp(logits) / np.sum(np.exp(logits), axis=-1, keepdims=True)
            return float(probs[0][1]) # Return probability of the positive class (label 1)
        except Exception as e:
            print(f"Error during model inference: {e}")
            return 0.0

def collect_training_data(filepath: str, key: str, context: str, label: int):
    """Appends a data sample with a verified label to a JSONL file for training."""
    data_point = { "key": key, "context": context, "label": label }
    try:
        with open(filepath, 'a') as f:
            f.write(json.dumps(data_point) + '\n')
    except IOError as e:
        print(f"Error writing to data collection file '{filepath}': {e}")


# --- Top-of-the-Class Training Pipeline ---

class KeyDataset(Dataset):
    """PyTorch Dataset for key-context pairs."""
    def __init__(self, encodings, labels):
        self.encodings = encodings
        self.labels = labels

    def __getitem__(self, idx):
        item = {key: torch.tensor(val[idx]) for key, val in self.encodings.items() if key != 'token_type_ids'}
        item['labels'] = torch.tensor(self.labels[idx])
        return item

    def __len__(self):
        return len(self.labels)

def model_init():
    """Initializes a new model for hyperparameter search."""
    return AutoModelForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=2)

def compute_metrics(pred):
    labels = pred.label_ids
    preds = pred.predictions.argmax(-1)
    f1 = f1_score(labels, preds, average='weighted')
    acc = accuracy_score(labels, preds)
    return {'accuracy': acc, 'f1': f1}

def train_and_export_model(data_file: str, output_dir: str = ".", do_hyperparameter_search: bool = False, k_folds: int = 5):
    """State-of-the-art pipeline: hyperparameter search, k-fold cross-validation, and quantized export."""
    if not ML_DEPS_AVAILABLE:
        print("Cannot train model: Missing one or more required ML libraries.")
        return

    print("\n--- [bold green]Starting State-of-the-Art Model Training Pipeline[/bold green] ---", flush=True)

    # 1. Load and Balance Dataset
    print(f"Step 1: Loading and balancing data from '{data_file}'...", flush=True)
    try:
        df = pd.read_json(data_file, lines=True)
        df.drop_duplicates(subset=['key', 'context'], inplace=True)
        
        label_counts = df['label'].value_counts()
        print(f"Initial counts: {label_counts.to_dict()}")
        min_count = label_counts.min()
        if min_count < k_folds:
             print(f"[bold red]Error: The smallest class has only {min_count} samples, which is less than the number of folds ({k_folds}).[/bold red]")
             print("Please collect more data or reduce the number of folds with --k-folds.")
             return

        df_balanced = pd.concat([
            df[df['label'] == 0].sample(n=min_count, random_state=42),
            df[df['label'] == 1].sample(n=min_count, random_state=42)
        ]).sample(frac=1, random_state=42)
        print(f"Balanced to {min_count} samples per class.")
    except Exception as e:
        print(f"Error loading or balancing data: {e}")
        return

    # 2. Preprocess and Tokenize
    print("Step 2: Preprocessing and tokenizing data...", flush=True)
    texts = [f"[KEY] {key} [CONTEXT] key_len:{len(key)} {re.sub(r'[^a-z0-9\s_:]', '', str(ctx).lower())}" for key, ctx in zip(df_balanced['key'], df_balanced['context'])]
    labels = df_balanced['label'].to_numpy()
    
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    
    # 3. Hyperparameter Search (Optional)
    best_params = {}
    if do_hyperparameter_search:
        print("\n--- [bold blue]Step 3: Performing Hyperparameter Search with Optuna[/bold blue] ---", flush=True)
        
        train_df, eval_df = train_test_split(df_balanced, test_size=0.2, random_state=42, stratify=df_balanced['label'])
        
        train_texts = [f"[KEY] {k} [CONTEXT] key_len:{len(k)} {re.sub(r'[^a-z0-9\s_:]', '', str(c).lower())}" for k,c in zip(train_df['key'], train_df['context'])]
        eval_texts = [f"[KEY] {k} [CONTEXT] key_len:{len(k)} {re.sub(r'[^a-z0-9\s_:]', '', str(c).lower())}" for k,c in zip(eval_df['key'], eval_df['context'])]
        
        train_encodings = tokenizer(train_texts, truncation=True, padding=True, max_length=MAX_LENGTH)
        eval_encodings = tokenizer(eval_texts, truncation=True, padding=True, max_length=MAX_LENGTH)
        
        train_dataset = KeyDataset(train_encodings, train_df['label'].tolist())
        eval_dataset = KeyDataset(eval_encodings, eval_df['label'].tolist())

        training_args = TrainingArguments(output_dir='./results_hpo', evaluation_strategy="epoch", disable_tqdm=True, num_train_epochs=3)

        trainer = Trainer(
            model=None,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=eval_dataset,
            tokenizer=tokenizer,
            model_init=model_init,
            compute_metrics=compute_metrics,
        )
        
        best_trial = trainer.hyperparameter_search(
            direction="maximize",
            backend="optuna",
            n_trials=20, # Number of trials to run
        )
        best_params = best_trial.hyperparameters
        print(f"Best hyperparameters found: {best_params}")
    else:
        print("\nStep 3: Skipping hyperparameter search. Using default parameters.", flush=True)
        best_params = {'learning_rate': 2e-5, 'num_train_epochs': 3, 'per_device_train_batch_size': 16}


    # 4. K-Fold Cross-Validation Training
    print(f"\n--- [bold blue]Step 4: Training with {k_folds}-Fold Cross-Validation[/bold blue] ---", flush=True)
    skf = StratifiedKFold(n_splits=k_folds, shuffle=True, random_state=42)
    fold_results = []
    best_f1 = -1
    best_model = None

    for fold, (train_idx, val_idx) in enumerate(skf.split(texts, labels)):
        print(f"\n--- Training Fold {fold+1}/{k_folds} ---")
        
        train_texts = [texts[i] for i in train_idx]
        val_texts = [texts[i] for i in val_idx]
        train_labels = labels[train_idx]
        val_labels = labels[val_idx]

        train_encodings = tokenizer(train_texts, truncation=True, padding=True, max_length=MAX_LENGTH)
        val_encodings = tokenizer(val_texts, truncation=True, padding=True, max_length=MAX_LENGTH)
        
        train_dataset = KeyDataset(train_encodings, train_labels.tolist())
        val_dataset = KeyDataset(val_encodings, val_labels.tolist())

        model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=2)
        
        training_args = TrainingArguments(
            output_dir=f'./results_fold_{fold}',
            num_train_epochs=best_params.get('num_train_epochs', 3),
            learning_rate=best_params.get('learning_rate', 2e-5),
            per_device_train_batch_size=best_params.get('per_device_train_batch_size', 16),
            per_device_eval_batch_size=64,
            warmup_ratio=0.1,
            weight_decay=0.01,
            logging_dir='./logs',
            logging_steps=10,
            evaluation_strategy="epoch",
            save_strategy="epoch",
            load_best_model_at_end=True,
            metric_for_best_model="f1",
            greater_is_better=True,
            callbacks=[EarlyStoppingCallback(early_stopping_patience=2)]
        )

        trainer = Trainer(
            model=model, args=training_args, train_dataset=train_dataset,
            eval_dataset=val_dataset, compute_metrics=compute_metrics
        )
        trainer.train()
        eval_metrics = trainer.evaluate()
        fold_results.append(eval_metrics)

        if eval_metrics['eval_f1'] > best_f1:
            best_f1 = eval_metrics['eval_f1']
            best_model = model
            print(f"New best model found in fold {fold+1} with F1-score: {best_f1:.4f}")

    # 5. Export Best Model and Quantize
    print("\n--- [bold blue]Step 5: Exporting & Quantizing Best Model[/bold blue] ---", flush=True)
    onnx_model_path = os.path.join(output_dir, "keyguardian_unquantized.onnx")
    quantized_model_path = os.path.join(output_dir, "keyguardian.onnx")
    
    dummy_input = tokenizer("test input", return_tensors="pt", padding=True, truncation=True, max_length=MAX_LENGTH)
    dummy_input.pop('token_type_ids', None) # DeBERTa doesn't use it

    torch.onnx.export(
        best_model,
        tuple(dummy_input.values()),
        onnx_model_path,
        input_names=list(dummy_input.keys()),
        output_names=['logits'],
        dynamic_axes={key: {0: 'batch_size'} for key in dummy_input.keys()},
        opset_version=13
    )

    print("Quantizing ONNX model to INT8 for maximum performance...", flush=True)
    quantize_dynamic(onnx_model_path, quantized_model_path, weight_type=QuantType.QInt8)
    os.remove(onnx_model_path) # Clean up

    # --- Final Report ---
    print("\n\n--- [bold green]State-of-the-Art Training Pipeline Complete![/bold green] ---")
    
    avg_metrics = {
        'avg_eval_loss': np.mean([r['eval_loss'] for r in fold_results]),
        'avg_eval_accuracy': np.mean([r['eval_accuracy'] for r in fold_results]),
        'avg_eval_f1': np.mean([r['eval_f1'] for r in fold_results])
    }
    print("\n[b]Cross-Validation Results (Averaged over {k_folds} folds):[/b]")
    print(f"  - Average Accuracy: {avg_metrics['avg_eval_accuracy']:.4f}")
    print(f"  - Average F1-Score: {avg_metrics['avg_eval_f1']:.4f}")

    # Detailed report from the best model
    print("\n[b]Detailed Report from Best Model (Fold with F1 = {best_f1:.4f}):[/b]")
    # Re-evaluate on its validation set to get preds
    _, val_idx_best = list(skf.split(texts, labels))[fold_results.index(max(fold_results, key=lambda x: x['eval_f1']))]
    val_texts_best = [texts[i] for i in val_idx_best]
    val_labels_best = labels[val_idx_best]
    
    best_trainer = Trainer(model=best_model)
    val_encodings_best = tokenizer(val_texts_best, truncation=True, padding=True, max_length=MAX_LENGTH)
    val_dataset_best = KeyDataset(val_encodings_best, val_labels_best.tolist())
    predictions = best_trainer.predict(val_dataset_best)
    
    y_pred = np.argmax(predictions.predictions, axis=-1)
    
    print(classification_report(val_labels_best, y_pred, target_names=['Not a Key (0)', 'Is a Key (1)']))
    print("[b]Confusion Matrix:[/b]")
    print(confusion_matrix(val_labels_best, y_pred))

    print(f"\n✅ Quantized ONNX model saved to: [cyan u]{quantized_model_path}[/cyan u]")
    print("The scanner is now ready to use this top-tier model with the '--ml-filter' flag.")


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="KeyGuardian SOTA ML Model Trainer")
    parser.add_argument('--train', action='store_true', help='Run the full, state-of-the-art training pipeline.')
    parser.add_argument('--data-file', type=str, default='training_data.jsonl', help='Path to the training data file (JSONL).')
    parser.add_argument('--hyperparameter-search', action='store_true', help='Perform Optuna hyperparameter search before training.')
    parser.add_argument('--k-folds', type=int, default=5, help='Number of folds for cross-validation.')
    args = parser.parse_args()

    if args.train:
        if not os.path.exists(args.data_file):
            print(f"Error: Data file '{args.data_file}' not found.")
            print("First, run a scan with '--collect-data' and '--validate' to generate high-quality training data.")
        else:
            train_and_export_model(args.data_file, do_hyperparameter_search=args.hyperparameter_search, k_folds=args.k_folds)
    else:
        print("This script is for training the ML model.\nUse 'python keyguardian.py --train' to start.")
