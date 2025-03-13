// Cargo.toml should include dependencies for paillier_rs, mnist, num-bigint, num-traits, and rand.
// [dependencies]
// paillier_rs = "0.x"         # replace with the actual version
// mnist = "0.7"
// num-bigint = "0.4"
// num-traits = "0.2"
// rand = "0.8"

use paillier_rs::keygen::{paillier_keygen, PublicKey, PrivateKey};
use paillier_rs::encrypt::paillier_encrypt;
use paillier_rs::decrypt::paillier_decrypt;
use paillier_rs::arithmetic::{paillier_add, paillier_scalar_mul};
use num_bigint::{BigUint, ToBigUint};
use num_traits::{One, ToPrimitive};
use mnist::{MnistBuilder};
use rand::Rng;

fn main() {
    // -------------------------------
    // 1. Load MNIST data (training and test sets)
    // -------------------------------
    let mnist = MnistBuilder::new()
        .label_format_digit()
        // For demo purposes, we use a smaller subset.
        .training_set_length(10000)
        .test_set_length(1000)
        .base_path("mnist_data")  // Ensure the MNIST files are in this folder.
        .finalize();

    let input_size = 28 * 28; // 784
    let num_classes = 10;
    let num_train = mnist.trn_lbl.len();
    let num_test = mnist.tst_lbl.len();

    // Convert training images to normalized f32 vectors.
    let train_images: Vec<Vec<f32>> = mnist.trn_img
        .chunks(input_size)
        .map(|chunk| chunk.iter().map(|&x| x as f32 / 255.0).collect())
        .collect();
    let train_labels: Vec<u8> = mnist.trn_lbl.clone();

    // Similarly for test images.
    let test_images: Vec<Vec<f32>> = mnist.tst_img
        .chunks(input_size)
        .map(|chunk| chunk.iter().map(|&x| x as f32 / 255.0).collect())
        .collect();
    let test_labels: Vec<u8> = mnist.tst_lbl.clone();

    // -------------------------------
    // 2. Train a simple logistic regression model in plaintext.
    //    Model: For input x, logits = W * x + b, and softmax is applied.
    // -------------------------------
    // Initialize weights (num_classes x input_size) and biases (num_classes).
    let mut weights = vec![vec![0.0f32; input_size]; num_classes];
    let mut biases = vec![0.0f32; num_classes];

    let mut rng = rand::thread_rng();
    // Initialize weights with small random values.
    for c in 0..num_classes {
        for i in 0..input_size {
            weights[c][i] = rng.gen_range(-0.01..0.01);
        }
        biases[c] = 0.0;
    }

    let epochs = 5;
    let learning_rate = 0.1;

    // Train using simple SGD (one example at a time).
    for epoch in 0..epochs {
        let mut total_loss = 0.0;
        // For demonstration, we loop in order. (Random shuffling would be better.)
        for (x, &label) in train_images.iter().zip(train_labels.iter()) {
            // Compute logits: for each class, dot(W[c], x) + bias[c]
            let mut logits = vec![0.0f32; num_classes];
            for c in 0..num_classes {
                let dot: f32 = weights[c].iter().zip(x.iter()).map(|(w, &xi)| w * xi).sum();
                logits[c] = dot + biases[c];
            }
            // Compute softmax probabilities.
            let max_logit = logits.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
            let exp_logits: Vec<f32> = logits.iter().map(|&l| (l - max_logit).exp()).collect();
            let sum_exp: f32 = exp_logits.iter().sum();
            let probs: Vec<f32> = exp_logits.iter().map(|&e| e / sum_exp).collect();

            // Cross-entropy loss.
            let loss = - (probs[label as usize] + 1e-10).ln();
            total_loss += loss;

            // Backpropagation: gradient w.r.t. logits is (probs - one_hot).
            let mut grad_logits = probs;
            grad_logits[label as usize] -= 1.0;

            // Update weights and biases.
            for c in 0..num_classes {
                for i in 0..input_size {
                    weights[c][i] -= learning_rate * grad_logits[c] * x[i];
                }
                biases[c] -= learning_rate * grad_logits[c];
            }
        }
        println!("Epoch {}: average loss = {}", epoch, total_loss / num_train as f32);
    }

    // -------------------------------
    // 3. Evaluate the trained model in plaintext.
    // -------------------------------
    let mut correct = 0;
    for (x, &label) in test_images.iter().zip(test_labels.iter()) {
        let mut logits = vec![0.0f32; num_classes];
        for c in 0..num_classes {
            let dot: f32 = weights[c].iter().zip(x.iter()).map(|(w, &xi)| w * xi).sum();
            logits[c] = dot + biases[c];
        }
        let predicted = logits
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
            .unwrap()
            .0;
        if predicted as u8 == label {
            correct += 1;
        }
    }
    let plaintext_accuracy = correct as f32 / num_test as f32;
    println!("Plaintext test accuracy: {}", plaintext_accuracy);

    // -------------------------------
    // 4. Quantize the trained model for homomorphic inference.
    //    Here we simply scale the floating-point parameters to non-negative integers.
    //    (In a real system you would handle negatives, rounding, and scaling more carefully.)
    // -------------------------------
    let scaling_factor: f32 = 1000.0;
    // For simplicity, we assume the trained weights and biases are non-negative.
    // (If not, you would need an encoding that handles signed numbers.)
    let quantized_weights: Vec<Vec<u32>> = weights.iter().map(|row| 
        row.iter().map(|&w| ((w * scaling_factor).round() as i32).max(0) as u32).collect()
    ).collect();
    let quantized_biases: Vec<u32> = biases.iter().map(|&b| ((b * scaling_factor).round() as i32).max(0) as u32).collect();

    // -------------------------------
    // 5. Set up Paillier for homomorphic inference.
    // -------------------------------
    let bits = 64; // For demo purposes only; use larger key sizes in practice.
    let (pubkey, privkey) = paillier_keygen(bits);

    // -------------------------------
    // 6. Evaluate the model over the test set using homomorphic inference.
    //    For each test image, we first convert pixel values (u8) to BigUint after encryption,
    //    then compute for each class: score = bias + sum_i (weight[i] * pixel[i]),
    //    using Paillier’s homomorphic scalar multiplication and addition.
    // -------------------------------
    let mut homomorphic_correct = 0;
    for (x, &label) in test_images.iter().zip(test_labels.iter()) {
        // Reconstruct the original pixel values (0–255) from normalized x.
        let pixel_values: Vec<u32> = x.iter().map(|&xi| (xi * 255.0).round() as u32).collect();

        // Encrypt each pixel value.
        let encrypted_pixels: Vec<BigUint> = pixel_values.iter()
            .map(|&px| {
                let val = px.to_biguint().unwrap();
                paillier_encrypt(&pubkey, &val)
            })
            .collect();

        // Compute encrypted scores for each class.
        let mut encrypted_scores: Vec<BigUint> = Vec::new();
        for c in 0..num_classes {
            let bias_val = quantized_biases[c].to_biguint().unwrap();
            let mut enc_sum = paillier_encrypt(&pubkey, &bias_val);
            for i in 0..input_size {
                let w = quantized_weights[c][i].to_biguint().unwrap();
                let enc_mul = paillier_scalar_mul(&encrypted_pixels[i], &w, &pubkey);
                enc_sum = paillier_add(&enc_sum, &enc_mul, &pubkey);
            }
            encrypted_scores.push(enc_sum);
        }
        // Decrypt the scores.
        let scores: Vec<u32> = encrypted_scores.iter()
            .map(|c| paillier_decrypt(&privkey, &pubkey, c).to_u32().unwrap())
            .collect();
        let predicted = scores.iter().enumerate().max_by_key(|&(_, score)| score).unwrap().0;
        if predicted as u8 == label {
            homomorphic_correct += 1;
        }
    }
    let homomorphic_accuracy = homomorphic_correct as f32 / num_test as f32;
    println!("Homomorphic inference test accuracy: {}", homomorphic_accuracy);
}
