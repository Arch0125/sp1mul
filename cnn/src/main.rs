use cnn::Conv2D;

/// Renders a feature map represented as a flattened byte vector in ASCII using a gradient.
/// It expects the bytes to represent a 2D image of dimensions `width` x `height`.
fn render_feature_map(bytes: &Vec<u8>, width: usize, height: usize) {
    // Define a gradient from low to high intensity.
    // You can modify these characters to any ASCII characters you prefer.
    let ascii_chars = [' ', '.', ':', '-', '=', '+', '*', '#', '%', '@'];
    
    println!("Rendered Feature Map:");
    for row in 0..height {
        for col in 0..width {
            // Get the pixel value at (row, col)
            let pixel = bytes[row * width + col];
            // Map pixel value (0-255) to an index in ascii_chars.
            let idx = (pixel as usize * (ascii_chars.len() - 1)) / 255;
            print!("{}", ascii_chars[idx]);
        }
        println!();
    }
    println!();
}

fn main() {
    // Define dimensions for an 8x8 image.
    let height = 8;
    let width = 8;

    // Create a sample input as a bytes vector.
    // Here we simulate an 8x8 grayscale image with values 0, 1, 2, ... 63.
    let input_bytes: Vec<u8> = (0..(height * width)).map(|x| x as u8).collect();
    println!("Input Bytes:\n{:?}\n", input_bytes);
    print!("Input Image:\n");
    render_feature_map(&input_bytes, width, height);

    // Initialize a Conv2D layer with 2 filters, each of size 3x3,
    // using a stride of 1 and padding of 1 (to maintain the input dimensions).
    let conv_layer = Conv2D::new(2, 3, 3, 1, 1);

    // Perform the forward pass using the bytes vector as input.
    let feature_maps = conv_layer.forward_from_bytes(&input_bytes, height, width);
    println!("Feature Maps (f32 values):\n{:?}\n", feature_maps);

    // Alternatively, get the output feature maps as byte vectors.
    let feature_maps_bytes = conv_layer.forward_from_bytes_as_bytes(&input_bytes, height, width);
    
    // Given the configuration (stride 1, padding 1, kernel 3x3), the output dimensions remain 8x8.
    let out_height = (height + 2 * conv_layer.padding - 3) / conv_layer.stride + 1;
    let out_width = (width + 2 * conv_layer.padding - 3) / conv_layer.stride + 1;

    // Print and render each feature map.
    for (i, fmap_bytes) in feature_maps_bytes.iter().enumerate() {
        println!("Feature Map {} as bytes (flattened):", i);
        println!("{:?}\n", fmap_bytes);
        render_feature_map(fmap_bytes, out_width, out_height);
    }
}
