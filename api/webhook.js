// Vercel Node.js API Route for WhatsApp Flow with Gemini API
// Place this file at: api/webhook.js

import { createHash, createHmac, createDecipheriv, createCipheriv, randomBytes } from 'crypto';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';

// --- CORS Headers ---
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
};

// WhatsApp API config
const WHATSAPP_TOKEN = process.env.WHATSAPP_TOKEN;
const WHATSAPP_PHONE_NUMBER_ID = process.env.WHATSAPP_PHONE_NUMBER_ID;
const WHATSAPP_API_VERSION = process.env.WHATSAPP_API_VERSION || 'v23.0';

// --- Utility Functions ---
function validateEnvironmentVars() {
  const requiredVars = [
    'PRIVATE_KEY',
    'VERIFY_TOKEN',
    'SUPABASE_URL',
    'GEMINI_API_KEY',
    'SUPABASE_S3_ENDPOINT',
    'SUPABASE_S3_ACCESS_KEY_ID',
    'SUPABASE_S3_SECRET_ACCESS_KEY',
    'WHATSAPP_TOKEN',
    'WHATSAPP_PHONE_NUMBER_ID'
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
  
  console.log('=== META ENCRYPTION DECRYPTION ===');
  console.log('Request body keys:', Object.keys(body));
  
  const { encrypted_aes_key, encrypted_flow_data, initial_vector } = body;
  if (!encrypted_aes_key || !encrypted_flow_data || !initial_vector) {
    throw new Error('Missing encrypted data fields in the request body. Required: encrypted_aes_key, encrypted_flow_data, initial_vector');
  }

  try {
    console.log('Step 1: Decrypting AES key with RSA-OAEP...');
    const encryptedAesKeyBuffer = Buffer.from(encrypted_aes_key, 'base64');
    const aesKeyBuffer = new Uint8Array(await crypto.subtle.decrypt({
      name: "RSA-OAEP"
    }, privateKey, encryptedAesKeyBuffer));
    console.log('✅ AES key decrypted successfully');

    console.log('Step 2: Preparing AES-GCM decryption...');
    const flowDataBuffer = Buffer.from(encrypted_flow_data, 'base64');
    const initialVectorBuffer = Buffer.from(initial_vector, 'base64');
    
    console.log('Flow data size:', flowDataBuffer.length);
    console.log('IV size:', initialVectorBuffer.length);

    const aesKey = await crypto.subtle.importKey("raw", aesKeyBuffer, {
      name: "AES-GCM"
    }, false, ["decrypt"]);
    console.log('✅ AES key imported successfully');

    console.log('Step 3: Decrypting flow data with AES-GCM...');
    const decryptedBuffer = await crypto.subtle.decrypt({
      name: "AES-GCM",
      iv: initialVectorBuffer,
      tagLength: 128
    }, aesKey, flowDataBuffer);
    console.log('✅ Flow data decrypted successfully');

    console.log('Step 4: Parsing decrypted JSON...');
    const decryptedJSONString = new TextDecoder().decode(decryptedBuffer);
    const decryptedBody = JSON.parse(decryptedJSONString);
    console.log('✅ JSON parsed successfully');

    return {
      decryptedBody,
      aesKeyBuffer,
      initialVectorBuffer
    };
  } catch (error) {
    console.error('❌ Meta encryption decryption failed:', error);
    throw new Error(`Meta decryption failed: ${error.message}`);
  }
}

async function encryptResponse(response, aesKeyBuffer, initialVectorBuffer) {
  const { webcrypto } = await import('crypto');
  const crypto = webcrypto;
  
  console.log('=== META ENCRYPTION ENCRYPTION ===');
  
  try {
    console.log('Step 1: Flipping IV for response encryption...');
    const flippedIv = new Uint8Array(initialVectorBuffer.map((byte) => ~byte & 0xFF));
    console.log('✅ IV flipped successfully');

    console.log('Step 2: Importing AES key for encryption...');
    const aesKey = await crypto.subtle.importKey("raw", aesKeyBuffer, {
      name: "AES-GCM"
    }, false, ["encrypt"]);
    console.log('✅ AES key imported for encryption');

    console.log('Step 3: Preparing response data...');
    const responseString = JSON.stringify(response);
    const responseBuffer = new TextEncoder().encode(responseString);
    console.log('Response size:', responseBuffer.length);

    console.log('Step 4: Encrypting response with AES-GCM...');
    const encryptedBuffer = await crypto.subtle.encrypt({
      name: "AES-GCM",
      iv: flippedIv,
      tagLength: 128
    }, aesKey, responseBuffer);
    console.log('✅ Response encrypted successfully');

    console.log('Step 5: Converting to base64...');
    const encryptedUint8Array = new Uint8Array(encryptedBuffer);
    const base64Response = Buffer.from(encryptedUint8Array).toString('base64');
    console.log('✅ Response converted to base64');
    
    return base64Response;
  } catch (error) {
    console.error('❌ Meta encryption failed:', error);
    throw new Error(`Meta encryption failed: ${error.message}`);
  }
}

// WhatsApp Image Decryption (CBC + HMAC 10-byte trailer, HMAC over iv|ciphertext)
async function decryptWhatsAppImage(imageData) {
  console.log('=== DECRYPT WHATSAPP IMAGE (CBC+HMAC-10) ===');
  console.log('Image data:', JSON.stringify(imageData, null, 2));

  try {
    const { cdn_url, encryption_metadata } = imageData;
    if (!cdn_url || !encryption_metadata) {
      throw new Error('Missing cdn_url or encryption_metadata');
    }

    const { encryption_key, hmac_key, iv, encrypted_hash, plaintext_hash } = encryption_metadata;

    const keyBuf = Buffer.from(encryption_key, 'base64'); // 32
    const macKeyBuf = Buffer.from(hmac_key, 'base64');    // 32
    const ivBuf = Buffer.from(iv, 'base64');              // 16

    if (keyBuf.length !== 32) throw new Error('Invalid encryption_key length');
    if (macKeyBuf.length !== 32) throw new Error('Invalid hmac_key length');
    if (ivBuf.length !== 16) throw new Error('Invalid iv length');

    console.log('Fetching encrypted image from CDN:', cdn_url);
    const response = await fetch(cdn_url);
    if (!response.ok) {
      throw new Error(`Failed to fetch image from CDN: ${response.status}`);
    }

    const encBuf = Buffer.from(await response.arrayBuffer());
    console.log('Encrypted image size:', encBuf.byteLength);

    if (encBuf.length <= 10) {
      throw new Error('Encrypted payload too small');
    }

    if (encrypted_hash) {
      const encSha = createHash('sha256').update(encBuf).digest('base64');
      console.log('Encrypted SHA256 (computed vs provided):', encSha, encrypted_hash);
      if (encSha !== encrypted_hash) {
        throw new Error('Encrypted hash mismatch');
      }
    }

    // Split ciphertext and appended MAC (last 10 bytes)
    const macTrailer = encBuf.subarray(encBuf.length - 10);
    const cipherText = encBuf.subarray(0, encBuf.length - 10);

    // HMAC-SHA256(iv || ciphertext), compare first 10 bytes
    const macFull = createHmac('sha256', macKeyBuf).update(ivBuf).update(cipherText).digest();
    const mac10 = macFull.subarray(0, 10);

    if (!mac10.equals(macTrailer)) {
      throw new Error('HMAC verification failed');
    }

    if (cipherText.length % 16 !== 0) {
      throw new Error(`Ciphertext length not a multiple of 16: ${cipherText.length}`);
    }

    // Decrypt AES-256-CBC with PKCS#7 padding
    let decrypted;
    try {
      const decipher = createDecipheriv('aes-256-cbc', keyBuf, ivBuf);
      decipher.setAutoPadding(true);
      decrypted = Buffer.concat([decipher.update(cipherText), decipher.final()]);
    } catch (e) {
      throw new Error(`AES decryption failed: ${e.message}`);
    }

    if (plaintext_hash) {
      const plainSha = createHash('sha256').update(decrypted).digest('base64');
      if (plainSha !== plaintext_hash) {
        console.warn('Plaintext hash mismatch (computed vs provided):', plainSha, plaintext_hash);
      } else {
        console.log('Plaintext hash verified.');
      }
    }

    console.log('Decryption successful. Size:', decrypted.length);
    return decrypted.toString('base64');
  } catch (error) {
    console.error('Error decrypting WhatsApp image:', error);
    throw new Error(`Image decryption failed: ${error.message}`);
  }
}

// Upload to Supabase Storage via S3-compatible API (SigV4)
async function uploadGeneratedImageToSupabase(base64Data, mimeType) {
  const supabaseUrl = process.env.SUPABASE_URL;
  const s3Endpoint = process.env.SUPABASE_S3_ENDPOINT; // e.g. https://<ref>.storage.supabase.co/storage/v1/s3
  const s3Region = process.env.SUPABASE_S3_REGION || 'us-east-1';
  const accessKeyId = process.env.SUPABASE_S3_ACCESS_KEY_ID;
  const secretAccessKey = process.env.SUPABASE_S3_SECRET_ACCESS_KEY;
  const bucket = process.env.SUPABASE_S3_BUCKET || 'generated-images';

  if (!supabaseUrl || !s3Endpoint || !accessKeyId || !secretAccessKey) {
    throw new Error('Missing SUPABASE_URL, SUPABASE_S3_ENDPOINT, or S3 credentials');
  }

  const buffer = Buffer.from(base64Data, 'base64');
  const ext = (mimeType && mimeType.split('/')[1]) || 'jpg';
  const filename = `generated-${Date.now()}.${ext}`;

  const s3 = new S3Client({
    region: s3Region,
    endpoint: s3Endpoint,
    credentials: { accessKeyId, secretAccessKey },
    forcePathStyle: true
  });

  await s3.send(new PutObjectCommand({
    Bucket: bucket,
    Key: filename,
    Body: buffer,
    ContentType: mimeType || 'image/jpeg'
  }));

  const baseUrl = supabaseUrl.replace(/\/+$/, '');
  const publicUrl = `${baseUrl}/storage/v1/object/public/${encodeURIComponent(bucket)}/${encodeURIComponent(filename)}`;
  console.log('Generated image uploaded (S3):', publicUrl);
  return publicUrl;
}

// Simple prompt creation function
function createSimplePrompt(productCategory, sceneDescription = null, priceOverlay = null) {
  let prompt = `Create a professional product photo of this ${productCategory}.`;
  
  if (sceneDescription && sceneDescription.trim()) {
    prompt += ` Show it in this setting: ${sceneDescription}.`;
  } else {
    prompt += ` Use a clean, professional background that complements the product.`;
  }
  
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
  
  let cleanBase64 = productImageBase64;
  if (productImageBase64.startsWith('data:')) {
    const base64Index = productImageBase64.indexOf(',');
    if (base64Index !== -1) {
      cleanBase64 = productImageBase64.substring(base64Index + 1);
      console.log("✅ Data URL prefix removed, new length:", cleanBase64.length);
    }
  }

  console.log("Step 2: Creating simple prompt...");
  
  const simplePrompt = createSimplePrompt(productCategory, sceneDescription, priceOverlay);
  console.log("Simple prompt:", simplePrompt);

  console.log("Step 3: Sending to Gemini API...");

  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-image-preview:generateContent?key=${apiKey}`;

  const requestBody = {
    contents: [
      {
        parts: [
          { text: simplePrompt },
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
      headers: { "Content-Type": "application/json" },
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

    for (const part of candidate.content.parts) {
      if (part.inlineData) {
        const generatedMimeType = part.inlineData.mimeType;
        const generatedBase64 = part.inlineData.data;
        console.log("✅ Image generated successfully");
        
        console.log("Step 5: Uploading generated image to Supabase (S3)...");
        try {
          const publicUrl = await uploadGeneratedImageToSupabase(generatedBase64, generatedMimeType);
          console.log("✅ Generated image uploaded to Supabase:", publicUrl);
          return publicUrl;
        } catch (uploadError) {
          console.error("Failed to upload generated image:", uploadError);
          console.log("⚠️ Fallback: returning base64 data URL");
          return `data:${generatedMimeType};base64,${generatedBase64}`;
        }
      }
    }

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

// --- Database helpers ---
async function saveToDatabase(finalData) {
  // This is a placeholder function - implement your database logic here
  // Examples:
  
  // For Supabase:
  // const { createClient } = await import('@supabase/supabase-js');
  // const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
  // const { data, error } = await supabase.from('flow_submissions').insert([finalData]);
  
  // For MongoDB:
  // const { MongoClient } = await import('mongodb');
  // const client = new MongoClient(process.env.MONGODB_URI);
  // await client.db('whatsapp_flow').collection('submissions').insertOne(finalData);
  
  // For simple file storage:
  const fs = await import('fs');
  const path = await import('path');
  
  const submissionsDir = path.join(process.cwd(), 'submissions');
  if (!fs.existsSync(submissionsDir)) {
    fs.mkdirSync(submissionsDir, { recursive: true });
  }
  
  const filename = `submission_${Date.now()}.json`;
  const filepath = path.join(submissionsDir, filename);
  
  fs.writeFileSync(filepath, JSON.stringify(finalData, null, 2));
  console.log(`✅ Data saved to file: ${filepath}`);
  
  return { success: true, filename };
}

// --- WhatsApp helpers ---
function getUserPhoneFromPayload(decryptedBody) {
  const candidates = [
    decryptedBody?.user?.wa_id,
    decryptedBody?.user?.phone,
    decryptedBody?.phone_number,
    decryptedBody?.mobile_number,
    decryptedBody?.data?.phone_number,
    decryptedBody?.data?.user_phone,
    decryptedBody?.data?.mobile_number
  ];

  const raw = candidates.find((v) => typeof v === 'string' && v.trim().length > 0);
  if (!raw) return null;

  const digits = raw.replace(/\D/g, '');
  if (!digits) return null;

  // Normalize India numbers: if 10 digits, prefix with 91
  if (digits.length === 10) return `91${digits}`;
  return digits; // assume already E.164 without plus
}

async function sendWhatsAppImageMessage(toE164, imageUrl, caption) {
  if (!toE164) throw new Error('Missing recipient phone number (E.164 format)');
  if (!imageUrl) throw new Error('Missing image URL');

  const url = `https://graph.facebook.com/${WHATSAPP_API_VERSION}/${WHATSAPP_PHONE_NUMBER_ID}/messages`;

  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${WHATSAPP_TOKEN}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      messaging_product: 'whatsapp',
      recipient_type: 'individual',
      to: toE164,
      type: 'image',
      image: {
        link: imageUrl,
        caption: caption || ''
      }
    })
  });

  const data = await resp.json();
  if (!resp.ok) {
    throw new Error(`WhatsApp send failed ${resp.status}: ${JSON.stringify(data)}`);
  }
  return data;
}

// --- Request Handlers ---
async function handleDataExchange(decryptedBody) {
  const { action, screen, data } = decryptedBody;
  console.log(`Processing action: ${action} for screen: ${screen}`);
  console.log('Data received:', JSON.stringify(data, null, 2));

  if (action === 'INIT') {
    return { screen: 'COLLECT_INFO', data: {} };
  }

  // Handle COMPLETE action - this is where the final payload comes
  if (action === 'complete') {
    console.log('=== COMPLETE ACTION RECEIVED ===');
    console.log('Final payload from complete action:', JSON.stringify(data, null, 2));
    
    // Extract the payload from the complete action
    const payload = data?.payload || data;
    
    if (payload) {
      console.log('=== PROCESSING FINAL PAYLOAD ===');
      console.log('Mobile Number:', payload.mobile_number);
      console.log('Product Category:', payload.product_category);
      console.log('Scene Description:', payload.scene_description);
      console.log('Price Overlay:', payload.price_overlay);
      console.log('Product Image:', payload.product_image ? 'present' : 'missing');
      
      // Here you can save the final data to your database
      // For example:
      // await saveToDatabase(payload);
      
      console.log('✅ Final payload processed successfully');
    }
    
    return { 
      screen: 'SUCCESS_SCREEN', 
      data: { 
        status: 'completed',
        message: 'Thank you for using our service!',
        final_data_received: true
      } 
    };
  }

  if (action === 'data_exchange') {
    console.log('=== DATA EXCHANGE ACTION ===');

    // Handle COLLECT_INFO screen navigation
    if (screen === 'COLLECT_INFO') {
      const { mobile_number, product_category } = data || {};
      
      if (!product_category || !product_category.trim()) {
        return {
          screen: 'COLLECT_INFO',
          data: { error_message: "Product category is required. Please specify what type of product this is." }
        };
      }

      return { 
        screen: 'COLLECT_IMAGE_SCENE', 
        data: { 
          mobile_number: mobile_number || '',
          product_category: product_category.trim()
        } 
      };
    }

    // Handle COLLECT_IMAGE_SCENE screen - process image and generate
    if (screen === 'COLLECT_IMAGE_SCENE') {
      if (data && typeof data === 'object') {
        const { scene_description, price_overlay, product_image, product_category, mobile_number } = data;

        console.log('=== FIELD VALIDATION ===');
        console.log('product_image:', product_image ? 'present' : 'MISSING (REQUIRED)');
        console.log('product_category:', product_category ? `"${product_category}"` : 'MISSING (REQUIRED)');
        console.log('scene_description:', scene_description ? `"${scene_description}"` : 'not provided (optional)');
        console.log('price_overlay:', price_overlay ? `"${price_overlay}"` : 'not provided (optional)');
        console.log('mobile_number:', mobile_number ? `"${mobile_number}"` : 'not provided (optional)');

        if (!product_image) {
          return {
            screen: 'COLLECT_IMAGE_SCENE',
            data: { error_message: "Product image is required. Please upload an image of your product." }
          };
        }

        if (!product_category || !product_category.trim()) {
          return {
            screen: 'COLLECT_INFO',
            data: { error_message: "Product category is required. Please specify what type of product this is." }
          };
        }

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
            data: { error_message: `Failed to process image: ${imageError.message}. Please try uploading the image again.` }
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

          // Send to user on WhatsApp using Supabase public URL
          try {
            const toPhone = getUserPhoneFromPayload(decryptedBody) || mobile_number;
            if (!toPhone) {
              console.warn('Phone number not found in payload; skipping WhatsApp send');
            } else {
              const caption = (price_overlay && price_overlay.trim())
                ? `${product_category.trim()} — ${price_overlay.trim()}`
                : product_category.trim();
              const waResp = await sendWhatsAppImageMessage(toPhone, imageUrl, caption);
              console.log('✅ WhatsApp image sent:', JSON.stringify(waResp));
            }
          } catch (sendErr) {
            console.error('❌ Failed to send WhatsApp image:', sendErr);
          }

          return { screen: 'SUCCESS_SCREEN', data: { image_url: imageUrl } };
        } catch (e) {
          console.error('❌ Image generation failed:', e);
          return {
            screen: 'COLLECT_IMAGE_SCENE',
            data: { error_message: `Image generation failed: ${e.message}. Please try again.` }
          };
        }
      } else {
        return { screen: 'COLLECT_INFO', data: { error_message: 'No data received. Please fill in the form.' } };
      }
    }

    // Handle SUCCESS_SCREEN completion
    if (screen === 'SUCCESS_SCREEN') {
      console.log('=== SUCCESS SCREEN COMPLETION ===');
      console.log('Final payload:', JSON.stringify(data, null, 2));
      
      // Here you can save the final data to your database
      // For now, just acknowledge completion
      return { 
        screen: 'SUCCESS_SCREEN', 
        data: { 
          status: 'completed',
          message: 'Thank you for using our service!'
        } 
      };
    }

    // Handle FINAL_SUBMIT screen - this is where we get the final payload
    if (screen === 'FINAL_SUBMIT') {
      console.log('=== FINAL SUBMIT SCREEN ===');
      console.log('Final payload from all screens:', JSON.stringify(data, null, 2));
      
      // Extract all the collected data
      const finalData = {
        mobile_number: data?.mobile_number || 'Not provided',
        product_category: data?.product_category || 'Not provided',
        scene_description: data?.scene_description || 'Not provided',
        price_overlay: data?.price_overlay || 'Not provided',
        product_image: data?.product_image ? 'Image uploaded' : 'No image',
        timestamp: new Date().toISOString()
      };
      
      console.log('=== PROCESSING FINAL SUBMISSION ===');
      console.log('Mobile Number:', finalData.mobile_number);
      console.log('Product Category:', finalData.product_category);
      console.log('Scene Description:', finalData.scene_description);
      console.log('Price Overlay:', finalData.price_overlay);
      console.log('Product Image:', finalData.product_image);
      console.log('Timestamp:', finalData.timestamp);
      
      // Save the final data to database/file
      try {
        const saveResult = await saveToDatabase(finalData);
        console.log('✅ Final submission processed and saved:', saveResult);
      } catch (saveError) {
        console.error('❌ Failed to save final data:', saveError);
        // Continue anyway - don't fail the flow
      }
      
      return { 
        screen: 'FINAL_SUBMIT', 
        data: { 
          status: 'submitted',
          message: 'Thank you for using our service!',
          submission_id: `sub_${Date.now()}`,
          final_data: finalData
        } 
      };
    }
  }

  if (action === 'BACK') {
    if (screen === 'COLLECT_IMAGE_SCENE') {
      return { screen: 'COLLECT_INFO', data: {} };
    }
    if (screen === 'SUCCESS_SCREEN') {
      return { screen: 'COLLECT_IMAGE_SCENE', data: {} };
    }
    if (screen === 'FINAL_SUBMIT') {
      return { screen: 'SUCCESS_SCREEN', data: {} };
    }
    return { screen: 'COLLECT_INFO', data: {} };
  }

  console.log(`Unhandled action/screen combination: ${action}/${screen}`);
  return { screen: 'COLLECT_INFO', data: { error_message: 'An unexpected error occurred.' } };
}

async function handleHealthCheck() {
  console.log('=== HEALTH CHECK REQUEST ===');
  return { 
    data: { 
      status: 'active',
      timestamp: new Date().toISOString(),
      version: '1.0.0'
    } 
  };
}

async function handleErrorNotification(decryptedBody) {
  console.log('Error notification received:', decryptedBody);
  return { data: { acknowledged: true } };
}

// --- Message Webhook Handlers ---
async function handleFlowResponse(interactiveData, messageContext) {
  console.log('=== FLOW RESPONSE RECEIVED ===');
  console.log('Interactive data:', JSON.stringify(interactiveData, null, 2));
  
  if (interactiveData.type !== 'nfm_reply') {
    console.log('Not a flow response, ignoring...');
    return;
  }
  
  const nfmReply = interactiveData.nfm_reply;
  if (nfmReply.name !== 'flow') {
    console.log('Not a flow nfm_reply, ignoring...');
    return;
  }
  
  console.log('=== PROCESSING FLOW RESPONSE ===');
  console.log('Flow body:', nfmReply.body);
  console.log('Response JSON:', nfmReply.response_json);
  
  try {
    // Parse the response_json which contains all the flow data
    const responseData = JSON.parse(nfmReply.response_json);
    console.log('Parsed response data:', JSON.stringify(responseData, null, 2));
    
    // Extract flow data
    const flowData = {
      flow_token: responseData.flow_token,
      mobile_number: responseData.mobile_number,
      product_category: responseData.product_category,
      scene_description: responseData.scene_description,
      price_overlay: responseData.price_overlay,
      product_image: responseData.product_image,
      timestamp: new Date().toISOString(),
      message_body: nfmReply.body
    };
    
    console.log('=== FINAL FLOW DATA ===');
    console.log('Flow Token:', flowData.flow_token);
    console.log('Mobile Number:', flowData.mobile_number);
    console.log('Product Category:', flowData.product_category);
    console.log('Scene Description:', flowData.scene_description);
    console.log('Price Overlay:', flowData.price_overlay);
    console.log('Product Image:', flowData.product_image ? 'present' : 'missing');
    console.log('Message Body:', flowData.message_body);
    console.log('Timestamp:', flowData.timestamp);
    
    // Check if we have all required data for AI generation
    if (flowData.product_image && flowData.product_category) {
      console.log('=== STARTING AI GENERATION PROCESS ===');
      
      try {
        let actualImageData;
        
        // Process the product image
        console.log('=== IMAGE PROCESSING ===');
        
        if (Array.isArray(flowData.product_image) && flowData.product_image.length > 0) {
          console.log('Processing WhatsApp image array');
          const firstImage = flowData.product_image[0];
          
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
        } else if (typeof flowData.product_image === 'string') {
          console.log('Processing direct base64 string...');
          actualImageData = flowData.product_image;
        } else {
          throw new Error('Invalid product_image format: expected array or string');
        }
        
        console.log('✅ Image processing successful');
        
        // Generate AI image
        console.log('🚀 Proceeding with AI image generation...');
        
        const imageUrl = await generateImageFromAi(
          actualImageData,
          flowData.product_category.trim(),
          flowData.scene_description && flowData.scene_description.trim() ? flowData.scene_description.trim() : null,
          flowData.price_overlay && flowData.price_overlay.trim() ? flowData.price_overlay.trim() : null
        );
        
        console.log('✅ AI image generation successful:', imageUrl);
        
        // Send to user on WhatsApp
        try {
          const toPhone = messageContext?.from || flowData.mobile_number;
          if (!toPhone) {
            console.warn('Phone number not found; skipping WhatsApp send');
          } else {
            const caption = (flowData.price_overlay && flowData.price_overlay.trim())
              ? `${flowData.product_category.trim()} — ${flowData.price_overlay.trim()}`
              : flowData.product_category.trim();
            const waResp = await sendWhatsAppImageMessage(toPhone, imageUrl, caption);
            console.log('✅ WhatsApp image sent:', JSON.stringify(waResp));
            
            // Add generated image URL to flow data
            flowData.generated_image_url = imageUrl;
            flowData.whatsapp_sent = true;
          }
        } catch (sendErr) {
          console.error('❌ Failed to send WhatsApp image:', sendErr);
          flowData.whatsapp_sent = false;
          flowData.whatsapp_error = sendErr.message;
        }
        
      } catch (aiError) {
        console.error('❌ AI generation failed:', aiError);
        flowData.ai_generation_failed = true;
        flowData.ai_error = aiError.message;
      }
    } else {
      console.log('⚠️ Missing required data for AI generation (product_image or product_category)');
      flowData.ai_generation_skipped = true;
    }
    
    // Save the flow submission (with AI results)
    try {
      const saveResult = await saveToDatabase(flowData);
      console.log('✅ Flow submission saved:', saveResult);
    } catch (saveError) {
      console.error('❌ Failed to save flow submission:', saveError);
    }
    
    return { success: true, flowData };
    
  } catch (parseError) {
    console.error('❌ Failed to parse response_json:', parseError);
    console.error('Raw response_json:', nfmReply.response_json);
    return { success: false, error: parseError.message };
  }
}

async function handleRegularMessage(message) {
  console.log('=== REGULAR MESSAGE RECEIVED ===');
  console.log('Message type:', message.type);
  console.log('Message content:', JSON.stringify(message, null, 2));
  
  // Handle other message types here if needed
  return { success: true, message: 'Regular message processed' };
}

async function handleMessageWebhook(requestBody) {
  console.log('=== MESSAGE WEBHOOK RECEIVED ===');
  console.log('Request body:', JSON.stringify(requestBody, null, 2));

  // Handle the webhook payload
  if (requestBody.object === 'whatsapp_business_account') {
    const entries = requestBody.entry || [];
    
    for (const entry of entries) {
      const changes = entry.changes || [];
      
      for (const change of changes) {
        if (change.field === 'messages') {
          const messages = change.value?.messages || [];
          
          for (const message of messages) {
            console.log('=== PROCESSING MESSAGE ===');
            console.log('Message ID:', message.id);
            console.log('From:', message.from);
            console.log('Type:', message.type);
            console.log('Timestamp:', message.timestamp);
            
            if (message.type === 'interactive') {
              // This is a flow response
              const result = await handleFlowResponse(message.interactive, message);
              console.log('Flow response result:', result);
            } else {
              // This is a regular message
              const result = await handleRegularMessage(message);
              console.log('Regular message result:', result);
            }
          }
        }
      }
    }
  }

  return { status: 'received' };
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
      console.log('=== WEBHOOK REQUEST RECEIVED ===');
      console.log('Request body keys:', Object.keys(requestBody));

      // Check if this is a message webhook (has 'object' field)
      if (requestBody.object === 'whatsapp_business_account') {
        console.log('=== PROCESSING AS MESSAGE WEBHOOK ===');
        const result = await handleMessageWebhook(requestBody);
        return res.status(200).json(result);
      }

      // Otherwise, process as flow webhook (encrypted data)
      console.log('=== PROCESSING AS FLOW WEBHOOK ===');
      
      try {
        const privateKeyPem = process.env.PRIVATE_KEY;
        if (!privateKeyPem) {
          throw new Error('PRIVATE_KEY environment variable is required for flow webhook');
        }
        
        const privateKey = await importPrivateKey(privateKeyPem);
        const { decryptedBody, aesKeyBuffer, initialVectorBuffer } = await decryptRequest(requestBody, privateKey);

        console.log('=== DECRYPTED FLOW DATA ===');
        console.log('Action:', decryptedBody.action);
        console.log('Screen:', decryptedBody.screen);
        console.log('Data keys:', Object.keys(decryptedBody.data || {}));

        let responsePayload;
        if (decryptedBody.action === 'ping') {
          console.log('Processing ping/health check...');
          responsePayload = await handleHealthCheck();
        } else if (decryptedBody.action === 'error_notification') {
          console.log('Processing error notification...');
          responsePayload = await handleErrorNotification(decryptedBody);
        } else if (decryptedBody.action === 'complete') {
          console.log('Processing complete action...');
          responsePayload = await handleDataExchange(decryptedBody);
        } else {
          console.log('Processing data exchange...');
          responsePayload = await handleDataExchange(decryptedBody);
        }

        console.log('=== ENCRYPTING RESPONSE ===');
        const encryptedResponse = await encryptResponse(responsePayload, aesKeyBuffer, initialVectorBuffer);
        console.log('✅ Response encrypted successfully');

        res.setHeader('Content-Type', 'application/json');
        return res.status(200).send(encryptedResponse);
        
      } catch (decryptError) {
        console.error('❌ Flow webhook decryption/processing failed:', decryptError);
        
        // For flow webhooks, we need to return an encrypted error response
        // But if decryption failed, we can't encrypt the response
        // So we return a plain error (this should be rare)
        return res.status(400).json({ 
          error: 'Decryption failed', 
          message: decryptError.message,
          timestamp: new Date().toISOString()
        });
      }
    } catch (error) {
      console.error('Error processing request:', error);
      return res.status(500).json({ error: `Internal Server Error: ${error.message}` });
    }
  }

  return res.status(405).json({ error: 'Method Not Allowed' });
}
