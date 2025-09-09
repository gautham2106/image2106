// Vercel Node.js API Route for WhatsApp Flow with Gemini API
// Place this file at: api/webhook.js

import { createHash, createDecipheriv, createCipheriv, randomBytes } from 'crypto';

// --- CORS Headers ---
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
};

// --- Utility Functions ---
function validateEnvironmentVars() {
  const requiredVars = [
    'PRIVATE_KEY',
    'VERIFY_TOKEN',
    'SUPABASE_URL',
    'SUPABASE_ANON_KEY',
    'GEMINI_API_KEY'
  ];
  const missing = requiredVars.filter((varName) => !process.env[varName]);
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
}

async function importPrivateKey(privateKeyPem) {
  const { webcrypto } = await import('crypto');
  const crypto = webcrypto;
  
  const pemHeader = "-----BEGIN PRIVATE KEY-----";
  const pemFooter = "-----END PRIVATE KEY-----";
  const pemContents = privateKeyPem.replace(pemHeader, "").replace(pemFooter, "").replace(/\s/g, "");
  const binaryDer = Uint8Array.from(Buffer.from(pemContents, 'base64'));
  
  return await crypto.subtle.importKey("pkcs8", binaryDer, {
    name: "RSA-OAEP",
    hash: "SHA-256"
  }, false, ["decrypt"]);
}

// --- Encryption/Decryption Functions ---
async function decryptRequest(body, privateKey) {
  const { webcrypto } = await import('crypto');
  const crypto = webcrypto;
  
  const { encrypted_aes_key, encrypted_flow_data, initial_vector } = body;
  if (!encrypted_aes_key || !encrypted_flow_data || !initial_vector) {
    throw new Error('Missing encrypted data fields in the request body');
  }

  try {
    const encryptedAesKeyBuffer = Buffer.from(encrypted_aes_key, 'base64');
    const aesKeyBuffer = new Uint8Array(await crypto.subtle.decrypt({
      name: "RSA-OAEP"
    }, privateKey, encryptedAesKeyBuffer));

    const flowDataBuffer = Buffer.from(encrypted_flow_data, 'base64');
    const initialVectorBuffer = Buffer.from(initial_vector, 'base64');

    const aesKey = await crypto.subtle.importKey("raw", aesKeyBuffer, {
      name: "AES-GCM"
    }, false, ["decrypt"]);

    const decryptedBuffer = await crypto.subtle.decrypt({
      name: "AES-GCM",
      iv: initialVectorBuffer,
      tagLength: 128
    }, aesKey, flowDataBuffer);

    const decryptedJSONString = new TextDecoder().decode(decryptedBuffer);
    const decryptedBody = JSON.parse(decryptedJSONString);

    return {
      decryptedBody,
      aesKeyBuffer,
      initialVectorBuffer
    };
  } catch (error) {
    console.error('Decryption failed:', error);
    throw new Error(`Decryption failed: ${error.message}`);
  }
}

async function encryptResponse(response, aesKeyBuffer, initialVectorBuffer) {
  const { webcrypto } = await import('crypto');
  const crypto = webcrypto;
  
  try {
    const flippedIv = new Uint8Array(initialVectorBuffer.map((byte) => ~byte & 0xFF));

    const aesKey = await crypto.subtle.importKey("raw", aesKeyBuffer, {
      name: "AES-GCM"
    }, false, ["encrypt"]);

    const responseString = JSON.stringify(response);
    const responseBuffer = new TextEncoder().encode(responseString);

    const encryptedBuffer = await crypto.subtle.encrypt({
      name: "AES-GCM",
      iv: flippedIv,
      tagLength: 128
    }, aesKey, responseBuffer);

    const encryptedUint8Array = new Uint8Array(encryptedBuffer);
    return Buffer.from(encryptedUint8Array).toString('base64');
  } catch (error) {
    console.error('Encryption failed:', error);
    throw new Error(`Encryption failed: ${error.message}`);
  }
}

// WhatsApp Image Decryption with multiple fallback strategies
async function decryptWhatsAppImage(imageData) {
  console.log('=== DECRYPT WHATSAPP IMAGE ===');
  console.log('Image data:', JSON.stringify(imageData, null, 2));
  
  try {
    const { cdn_url, encryption_metadata } = imageData;
    const { encryption_key, hmac_key, iv } = encryption_metadata;
    
    console.log('Fetching encrypted image from CDN:', cdn_url);
    
    const response = await fetch(cdn_url);
    if (!response.ok) {
      throw new Error(`Failed to fetch image from CDN: ${response.status}`);
    }
    
    const encryptedArrayBuffer = await response.arrayBuffer();
    console.log('Encrypted image size:', encryptedArrayBuffer.byteLength);
    
    const encryptedBuffer = Buffer.from(encryptedArrayBuffer);
    const encryptionKeyBuffer = Buffer.from(encryption_key, 'base64');
    const ivBuffer = Buffer.from(iv, 'base64');
    
    console.log('Trying multiple decryption strategies...');
    
    // Strategy 1: Try direct decryption (no HMAC separation)
    try {
      console.log('Strategy 1: Direct decryption without HMAC separation');
      const decipher1 = createDecipheriv('aes-256-cbc', encryptionKeyBuffer, ivBuffer);
      decipher1.setAutoPadding(true);
      
      const decrypted1 = Buffer.concat([
        decipher1.update(encryptedBuffer),
        decipher1.final()
      ]);
      
      console.log('Strategy 1 successful! Decrypted size:', decrypted1.length);
      return decrypted1.toString('base64');
    } catch (error1) {
      console.log('Strategy 1 failed:', error1.message);
    }
    
    // Strategy 2: Remove HMAC (last 32 bytes) then decrypt
    try {
      console.log('Strategy 2: Remove HMAC (32 bytes) then decrypt');
      const mediaData = encryptedBuffer.slice(0, -32);
      const decipher2 = createDecipheriv('aes-256-cbc', encryptionKeyBuffer, ivBuffer);
      decipher2.setAutoPadding(true);
      
      const decrypted2 = Buffer.concat([
        decipher2.update(mediaData),
        decipher2.final()
      ]);
      
      console.log('Strategy 2 successful! Decrypted size:', decrypted2.length);
      return decrypted2.toString('base64');
    } catch (error2) {
      console.log('Strategy 2 failed:', error2.message);
    }
    
    // Strategy 3: Manual padding with direct decryption
    try {
      console.log('Strategy 3: Manual padding handling (no HMAC)');
      const decipher3 = createDecipheriv('aes-256-cbc', encryptionKeyBuffer, ivBuffer);
      decipher3.setAutoPadding(false);
      
      const decryptedWithPadding = Buffer.concat([
        decipher3.update(encryptedBuffer),
        decipher3.final()
      ]);
      
      const paddingLength = decryptedWithPadding[decryptedWithPadding.length - 1];
      const decrypted3 = paddingLength > 0 && paddingLength <= 16 
        ? decryptedWithPadding.slice(0, -paddingLength)
        : decryptedWithPadding;
      
      console.log('Strategy 3 successful! Decrypted size:', decrypted3.length);
      return decrypted3.toString('base64');
    } catch (error3) {
      console.log('Strategy 3 failed:', error3.message);
    }
    
    // Strategy 4: Manual padding with HMAC removal
    try {
      console.log('Strategy 4: Manual padding with HMAC removal');
      const mediaData = encryptedBuffer.slice(0, -32);
      const decipher4 = createDecipheriv('aes-256-cbc', encryptionKeyBuffer, ivBuffer);
      decipher4.setAutoPadding(false);
      
      const decryptedWithPadding = Buffer.concat([
        decipher4.update(mediaData),
        decipher4.final()
      ]);
      
      const paddingLength = decryptedWithPadding[decryptedWithPadding.length - 1];
      const decrypted4 = paddingLength > 0 && paddingLength <= 16 
        ? decryptedWithPadding.slice(0, -paddingLength)
        : decryptedWithPadding;
      
      console.log('Strategy 4 successful! Decrypted size:', decrypted4.length);
      return decrypted4.toString('base64');
    } catch (error4) {
      console.log('Strategy 4 failed:', error4.message);
    }
    
    // Strategy 5: Try with different HMAC sizes
    for (const hmacSize of [0, 16, 20, 32, 64]) {
      try {
        console.log(`Strategy 5.${hmacSize}: HMAC size ${hmacSize} bytes`);
        const mediaData = hmacSize > 0 ? encryptedBuffer.slice(0, -hmacSize) : encryptedBuffer;
        const decipher5 = createDecipheriv('aes-256-cbc', encryptionKeyBuffer, ivBuffer);
        decipher5.setAutoPadding(true);
        
        const decrypted5 = Buffer.concat([
          decipher5.update(mediaData),
          decipher5.final()
        ]);
        
        console.log(`Strategy 5.${hmacSize} successful! Decrypted size:`, decrypted5.length);
        return decrypted5.toString('base64');
      } catch (error5) {
        console.log(`Strategy 5.${hmacSize} failed:`, error5.message);
      }
    }
    
    throw new Error('All decryption strategies failed');
    
  } catch (error) {
    console.error('Error decrypting WhatsApp image:', error);
    throw new Error(`Image decryption failed: ${error.message}`);
  }
}

// Helper function to upload generated image to Supabase
async function uploadGeneratedImageToSupabase(base64Data, mimeType) {
  const { createClient } = await import('@supabase/supabase-js');
  const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
  );

  try {
    const buffer = Buffer.from(base64Data, 'base64');
    const filename = `generated-${Date.now()}.${mimeType.split('/')[1]}`;
    
    const { data, error } = await supabase.storage
      .from('generated-images')
      .upload(filename, buffer, {
        contentType: mimeType,
        upsert: false
      });

    if (error) {
      console.error('Supabase generated upload error:', error);
      throw new Error(`Generated upload failed: ${error.message}`);
    }

    const { data: publicUrlData } = supabase.storage
      .from('generated-images')
      .getPublicUrl(filename);

    console.log('Generated image uploaded:', publicUrlData.publicUrl);
    return publicUrlData.publicUrl;
  } catch (error) {
    console.error('Error uploading generated image to Supabase:', error);
    throw error;
  }
}

// Simple prompt creation function
function createSimplePrompt(productCategory, sceneDescription = null, priceOverlay = null) {
  let prompt = `Create a professional product photo of this ${productCategory}.`;
  
  // Add scene description if provided
  if (sceneDescription && sceneDescription.trim()) {
    prompt += ` Show it in this setting: ${sceneDescription}.`;
  } else {
    prompt += ` Use a clean, professional background that complements the product.`;
  }
  
  // Add price overlay instruction if provided
  if (priceOverlay && priceOverlay.trim()) {
    prompt += ` Include the price "${priceOverlay}" as a stylish overlay on the image.`;
  }
  
  prompt += ` Make it look like a high-quality commercial product photo suitable for marketing and sales.`;
  
  return prompt;
}

// Simplified Gemini API call
async function generateImageFromAi(productImageBase64, productCategory, sceneDescription = null, priceOverlay = null) {
  console.log('=== GENERATE IMAGE FROM AI ===');
  console.log('Parameters:');
  console.log('- productImageBase64 length:', productImageBase64 ? productImageBase64.length : 0);
  console.log('- productCategory:', productCategory || 'MISSING');
  console.log('- sceneDescription:', sceneDescription || 'not provided');
  console.log('- priceOverlay:', priceOverlay || 'not provided');
  
  // Validate required parameters
  if (!productImageBase64 || typeof productImageBase64 !== 'string') {
    throw new Error("Product image data is missing or invalid");
  }
  
  if (!productCategory || typeof productCategory !== 'string') {
    throw new Error("Product category is required");
  }

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error("Missing GEMINI_API_KEY environment variable");
  }

  console.log("Step 1: Cleaning base64 data...");
  
  // Clean the base64 data - remove data URL prefix if present
  let cleanBase64 = productImageBase64;
  if (productImageBase64.startsWith('data:')) {
    const base64Index = productImageBase64.indexOf(',');
    if (base64Index !== -1) {
      cleanBase64 = productImageBase64.substring(base64Index + 1);
      console.log("✅ Data URL prefix removed, new length:", cleanBase64.length);
    }
  }

  console.log("Step 2: Creating simple prompt...");
  
  // Create simple prompt
  const simplePrompt = createSimplePrompt(productCategory, sceneDescription, priceOverlay);
  console.log("Simple prompt:", simplePrompt);

  console.log("Step 3: Sending to Gemini API...");

  // Use the Gemini REST API endpoint for image generation
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-image-preview:generateContent?key=${apiKey}`;

  // Build request body
  const requestBody = {
    contents: [
      {
        parts: [
          {
            text: simplePrompt
          },
          {
            inlineData: {
              mimeType: "image/jpeg",
              data: cleanBase64
            }
          }
        ]
      }
    ],
    generationConfig: {
      temperature: 0.8,
      maxOutputTokens: 1024,
      topP: 0.9,
      topK: 40
    }
  };

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(requestBody)
    });

    console.log("Response status:", response.status);

    if (!response.ok) {
      const errorText = await response.text();
      console.error("Gemini API error response:", errorText);
      throw new Error(`Gemini API failed (${response.status}): ${errorText}`);
    }

    const responseData = await response.json();
    console.log("✅ Gemini API response received");

    const candidate = responseData?.candidates?.[0];
    if (!candidate?.content?.parts) {
      throw new Error("No response parts found in Gemini API response");
    }

    console.log("Step 4: Processing generated image...");

    // Look for image data in response parts
    for (const part of candidate.content.parts) {
      if (part.inlineData) {
        const generatedMimeType = part.inlineData.mimeType;
        const generatedBase64 = part.inlineData.data;
        console.log("✅ Image generated successfully");
        
        console.log("Step 5: Uploading generated image to Supabase...");
        
        // Upload generated image to Supabase
        try {
          const publicUrl = await uploadGeneratedImageToSupabase(generatedBase64, generatedMimeType);
          console.log("✅ Generated image uploaded to Supabase:", publicUrl);
          return publicUrl;
        } catch (uploadError) {
          console.error("Failed to upload generated image:", uploadError);
          // Fallback: return base64 data URL
          console.log("⚠️ Fallback: returning base64 data URL");
          return `data:${generatedMimeType};base64,${generatedBase64}`;
        }
      }
    }

    // If no image found, check for text response
    const textPart = candidate.content.parts.find((p) => p.text);
    if (textPart) {
      throw new Error(`Model returned text instead of image: ${textPart.text}`);
    }

    throw new Error("No image data found in Gemini API response");
  } catch (error) {
    console.error('❌ Error in generateImageFromAi:', error);
    throw error;
  }
}

// --- Request Handlers ---
async function handleDataExchange(decryptedBody) {
  const { action, screen, data } = decryptedBody;
  console.log(`Processing action: ${action} for screen: ${screen}`);
  console.log('Data received:', JSON.stringify(data, null, 2));

  if (action === 'INIT') {
    return {
      screen: 'COLLECT_INFO',
      data: {}
    };
  }

  if (action === 'data_exchange') {
    console.log('=== DATA EXCHANGE ACTION ===');

    // Check if we have the required fields for image generation
    if (data && typeof data === 'object') {
      const { scene_description, price_overlay, product_image, product_category } = data;

      console.log('=== FIELD VALIDATION ===');
      console.log('product_image:', product_image ? 'present' : 'MISSING (REQUIRED)');
      console.log('product_category:', product_category ? `"${product_category}"` : 'MISSING (REQUIRED)');
      console.log('scene_description:', scene_description ? `"${scene_description}"` : 'not provided (optional)');
      console.log('price_overlay:', price_overlay ? `"${price_overlay}"` : 'not provided (optional)');

      // Validate mandatory fields
      if (!product_image) {
        return {
          screen: 'COLLECT_IMAGE_SCENE',
          data: {
            error_message: "Product image is required. Please upload an image of your product."
          }
        };
      }

      if (!product_category || !product_category.trim()) {
        return {
          screen: 'COLLECT_INFO',
          data: {
            error_message: "Product category is required. Please specify what type of product this is."
          }
        };
      }

      // Process image data
      let actualImageData;
      try {
        console.log('=== IMAGE PROCESSING ===');
        
        if (Array.isArray(product_image) && product_image.length > 0) {
          console.log('Processing WhatsApp image array');
          const firstImage = product_image[0];
          
          if (firstImage.encryption_metadata) {
            console.log('Decrypting WhatsApp encrypted image...');
            actualImageData = await decryptWhatsAppImage(firstImage);
          } else if (firstImage.cdn_url) {
            console.log('Fetching unencrypted image from CDN...');
            const response = await fetch(firstImage.cdn_url);
            if (!response.ok) {
              throw new Error(`Failed to fetch image: ${response.status}`);
            }
            const arrayBuffer = await response.arrayBuffer();
            actualImageData = Buffer.from(arrayBuffer).toString('base64');
          } else {
            throw new Error('Invalid image format: no cdn_url or encryption_metadata found');
          }
        } else if (typeof product_image === 'string') {
          console.log('Processing direct base64 string...');
          actualImageData = product_image;
        } else {
          throw new Error('Invalid product_image format: expected array or string');
        }
        
        console.log('✅ Image processing successful');
        
      } catch (imageError) {
        console.error('❌ Image processing failed:', imageError);
        return {
          screen: 'COLLECT_IMAGE_SCENE',
          data: {
            error_message: `Failed to process image: ${imageError.message}. Please try uploading the image again.`
          }
        };
      }

      console.log('🚀 Proceeding with image generation...');
      
      try {
        const imageUrl = await generateImageFromAi(
          actualImageData,
          product_category.trim(),
          scene_description && scene_description.trim() ? scene_description.trim() : null,
          price_overlay && price_overlay.trim() ? price_overlay.trim() : null
        );
        
        console.log('✅ Image generation successful:', imageUrl);
        return {
          screen: 'SUCCESS_SCREEN',
          data: {
            image_url: imageUrl
          }
        };
      } catch (e) {
        console.error('❌ Image generation failed:', e);
        return {
          screen: 'COLLECT_IMAGE_SCENE',
          data: {
            error_message: `Image generation failed: ${e.message}. Please try again.`
          }
        };
      }
    } else {
      return {
        screen: 'COLLECT_INFO',
        data: {
          error_message: 'No data received. Please fill in the form.'
        }
      };
    }
  }

  if (action === 'BACK') {
    if (screen === 'COLLECT_IMAGE_SCENE') {
      return {
        screen: 'COLLECT_INFO',
        data: {}
      };
    }
    return {
      screen: 'COLLECT_INFO',
      data: {}
    };
  }

  console.log(`Unhandled action/screen combination: ${action}/${screen}`);
  return {
    screen: 'COLLECT_INFO',
    data: {
      error_message: 'An unexpected error occurred.'
    }
  };
}

async function handleHealthCheck() {
  return {
    data: {
      status: 'active'
    }
  };
}

async function handleErrorNotification(decryptedBody) {
  console.log('Error notification received:', decryptedBody);
  return {
    data: {
      acknowledged: true
    }
  };
}

// --- Main Vercel API Handler ---
export default async function handler(req, res) {
  // Handle CORS
  if (req.method === 'OPTIONS') {
    res.status(200);
    Object.entries(corsHeaders).forEach(([key, value]) => {
      res.setHeader(key, value);
    });
    return res.end();
  }

  // Set CORS headers for all responses
  Object.entries(corsHeaders).forEach(([key, value]) => {
    res.setHeader(key, value);
  });

  try {
    validateEnvironmentVars();
  } catch (error) {
    console.error('Environment validation failed:', error.message);
    return res.status(500).json({ error: 'Internal Server Error' });
  }

  if (req.method === 'GET') {
    const { query } = req;
    const mode = query['hub.mode'];
    const token = query['hub.verify_token'];
    const challenge = query['hub.challenge'];
    const verifyToken = process.env.VERIFY_TOKEN;

    if (mode === 'subscribe' && token === verifyToken && challenge) {
      res.setHeader('Content-Type', 'text/plain');
      return res.status(200).send(challenge);
    } else {
      return res.status(403).json({ error: 'Forbidden' });
    }
  }

  if (req.method === 'POST') {
    try {
      const requestBody = req.body;

      const privateKeyPem = process.env.PRIVATE_KEY;
      const privateKey = await importPrivateKey(privateKeyPem);

      const { decryptedBody, aesKeyBuffer, initialVectorBuffer } = await decryptRequest(requestBody, privateKey);

      let responsePayload;
      if (decryptedBody.action === 'ping') {
        responsePayload = await handleHealthCheck();
      } else if (decryptedBody.action === 'error_notification') {
        responsePayload = await handleErrorNotification(decryptedBody);
      } else {
        responsePayload = await handleDataExchange(decryptedBody);
      }

      const encryptedResponse = await encryptResponse(responsePayload, aesKeyBuffer, initialVectorBuffer);

      res.setHeader('Content-Type', 'application/json');
      return res.status(200).send(encryptedResponse);
    } catch (error) {
      console.error('Error processing request:', error);
      return res.status(500).json({ error: `Internal Server Error: ${error.message}` });
    }
  }

  return res.status(405).json({ error: 'Method Not Allowed' });
}
