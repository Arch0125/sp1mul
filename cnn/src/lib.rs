use ndarray::prelude::*;
use rand::Rng;

/// A simple 2D convolution layer for a single-channel input.
pub struct Conv2D {
    /// Filter weights with shape (num_filters, kernel_height, kernel_width)
    pub weight: Array3<f32>,
    /// Bias for each filter, shape (num_filters)
    pub bias: Array1<f32>,
    /// Stride for the convolution
    pub stride: usize,
    /// Padding (number of zeros added to each border)
    pub padding: usize,
}

impl Conv2D {
    /// Creates a new Conv2D layer with random weights and biases.
    ///
    /// # Arguments
    /// * `num_filters` - The number of filters (output feature maps)
    /// * `kernel_h` - Height of the convolution kernel
    /// * `kernel_w` - Width of the convolution kernel
    /// * `stride` - Stride of the convolution
    /// * `padding` - Padding around the input image
    pub fn new(num_filters: usize, kernel_h: usize, kernel_w: usize, stride: usize, padding: usize) -> Self {
        let mut rng = rand::thread_rng();
        let weight = Array::from_shape_fn((num_filters, kernel_h, kernel_w), |_| rng.gen_range(-1.0..1.0));
        let bias = Array::from_shape_fn(num_filters, |_| rng.gen_range(-1.0..1.0));
        Conv2D { weight, bias, stride, padding }
    }

    /// Performs the forward pass of the convolution layer.
    ///
    /// # Arguments
    /// * `input` - A 2D array representing the input image
    ///
    /// # Returns
    /// A 3D array containing the feature maps with dimensions:
    /// (num_filters, output_height, output_width)
    pub fn forward(&self, input: &Array2<f32>) -> Array3<f32> {
        let (in_h, in_w) = (input.dim().0, input.dim().1);
        let (num_filters, kernel_h, kernel_w) = (self.weight.dim().0, self.weight.dim().1, self.weight.dim().2);
        let out_h = (in_h + 2 * self.padding - kernel_h) / self.stride + 1;
        let out_w = (in_w + 2 * self.padding - kernel_w) / self.stride + 1;

        // Create a padded input (with zeros) to handle border cases.
        let mut padded = Array2::<f32>::zeros((in_h + 2 * self.padding, in_w + 2 * self.padding));
        padded.slice_mut(s![self.padding..self.padding + in_h, self.padding..self.padding + in_w])
              .assign(input);

        // Initialize the output feature maps.
        let mut output = Array3::<f32>::zeros((num_filters, out_h, out_w));
        for f in 0..num_filters {
            for i in 0..out_h {
                for j in 0..out_w {
                    let start_i = i * self.stride;
                    let start_j = j * self.stride;
                    // Extract the region of interest from the padded input.
                    let region = padded.slice(s![start_i..start_i + kernel_h, start_j..start_j + kernel_w]);
                    // Perform element-wise multiplication and sum the result, then add bias.
                    let conv_sum = (&region * &self.weight.slice(s![f, .., ..])).sum() + self.bias[f];
                    // Apply ReLU activation (i.e., max(0, conv_sum)).
                    output[[f, i, j]] = conv_sum.max(0.0);
                }
            }
        }
        output
    }

    /// Performs the forward pass of the convolution layer and returns the feature maps as a vector of bytes.
    ///
    /// This method normalizes each feature map so that its maximum value maps to 255,
    /// then converts the floating-point values into u8 values.
    ///
    /// # Arguments
    /// * `input` - A 2D array representing the input image
    ///
    /// # Returns
    /// A vector where each element is a flattened byte vector representing a feature map.
    pub fn forward_as_bytes(&self, input: &Array2<f32>) -> Vec<Vec<u8>> {
        let feature_maps = self.forward(input);
        let num_filters = feature_maps.dim().0;
        let mut output_bytes = Vec::with_capacity(num_filters);

        // Iterate over each filter's feature map.
        for fm in feature_maps.outer_iter() {
            // Find the maximum value in the feature map for normalization.
            let max_val = fm.iter().cloned().fold(0.0, f32::max);
            // If max is greater than 0, scale so that max becomes 255.
            let scale = if max_val > 0.0 { 255.0 / max_val } else { 1.0 };

            // Convert each value to a byte.
            let bytes: Vec<u8> = fm.iter()
                .map(|&val| {
                    let scaled = (val * scale).round();
                    // Clamp the scaled value between 0 and 255.
                    scaled.min(255.0).max(0.0) as u8
                })
                .collect();

            output_bytes.push(bytes);
        }
        output_bytes
    }

    /// Converts a bytes vector into a 2D input array for the CNN.
    ///
    /// # Arguments
    /// * `input_bytes` - A slice of bytes representing the image.
    /// * `height` - The height of the image.
    /// * `width` - The width of the image.
    ///
    /// # Returns
    /// An Array2<f32> where each element is the floating-point representation of the byte.
    pub fn input_from_bytes(input_bytes: &[u8], height: usize, width: usize) -> Array2<f32> {
        assert_eq!(input_bytes.len(), height * width, "The length of input_bytes must equal height * width");
        let data: Vec<f32> = input_bytes.iter().map(|&b| b as f32).collect();
        Array::from_shape_vec((height, width), data).expect("Error converting bytes to array")
    }

    /// Performs the forward pass of the convolution layer using input provided as a bytes vector.
    ///
    /// # Arguments
    /// * `input_bytes` - A slice of bytes representing the image.
    /// * `height` - The height of the image.
    /// * `width` - The width of the image.
    ///
    /// # Returns
    /// A 3D array containing the feature maps with dimensions:
    /// (num_filters, output_height, output_width)
    pub fn forward_from_bytes(&self, input_bytes: &[u8], height: usize, width: usize) -> Array3<f32> {
        let input = Self::input_from_bytes(input_bytes, height, width);
        self.forward(&input)
    }

    /// Performs the forward pass of the convolution layer using input provided as a bytes vector,
    /// and returns the output feature maps as a vector of bytes.
    ///
    /// # Arguments
    /// * `input_bytes` - A slice of bytes representing the image.
    /// * `height` - The height of the image.
    /// * `width` - The width of the image.
    ///
    /// # Returns
    /// A vector where each element is a flattened byte vector representing a feature map.
    pub fn forward_from_bytes_as_bytes(&self, input_bytes: &[u8], height: usize, width: usize) -> Vec<Vec<u8>> {
        let input = Self::input_from_bytes(input_bytes, height, width);
        self.forward_as_bytes(&input)
    }
}
