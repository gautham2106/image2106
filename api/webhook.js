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

// Fetch configuration
const FETCH_TIMEOUT = parseInt(process.env.WHATSAPP_FETCH_TIMEOUT) || 30000; // 30 seconds
const FETCH_RETRIES = parseInt(process.env.WHATSAPP_FETCH_RETRIES) || 3;
const RETRY_DELAY = parseInt(process.env.WHATSAPP_RETRY_DELAY) || 2000; // 2 seconds

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

// Enhanced fetch with timeout and retry logic
async function fetchWithTimeoutAndRetry(url, options = {}) {
  const {
    timeout = FETCH_TIMEOUT,
    retries = FETCH_RETRIES,
    retryDelay = RETRY_DELAY,
    headers = {}
  } = options;

  let lastError;

  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      console.log(`Fetch attempt ${attempt}/${retries} for URL: ${url}`);
      
      // Create abort controller for timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => {
        console.log(`⏱️ Request timeout after ${timeout}ms, aborting...`);
        controller.abort();
      }, timeout);

      const response = await fetch(url, {
        headers: {
          'User-Agent': 'WhatsApp/2.24.1.78 (compatible; WhatsAppBot/1.0)',
          'Accept': '*/*',
          'Accept-Encoding': 'gzip, deflate, br',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
          ...headers
        },
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const buffer = Buffer.from(await response.arrayBuffer());
      console.log(`✅ Fetch successful on attempt ${attempt}, size: ${buffer.length} bytes`);
      return buffer;

    } catch (error) {
      lastError = error;
      console.error(`❌ Fetch attempt ${attempt} failed:`, error.message);

      // Check error type
      if (error.name === 'AbortError') {
        console.log(`⏱️ Request timed out after ${timeout}ms`);
      } else if (error.message.includes('HTTP 4')) {
        console.log('🚫 Client error (4xx), not retrying');
        break;
      } else if (error.message.includes('HTTP 5')) {
        console.log('🔄 Server error (5xx), will retry');
      } else if (error.name === 'TypeError' && error.message.includes('fetch')) {
        console.log('🌐 Network error, will retry');
      }

      // Wait before retry (except on last attempt)
      if (attempt < retries) {
        const delay = retryDelay * attempt; // Exponential backoff
        console.log(`⏳ Waiting ${delay}ms before retry...`);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }

  throw new Error(`Failed to fetch after ${retries} attempts. Last error: ${lastError.message}`);
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

// Enhanced WhatsApp Image Decryption with better error handling
async function performImageDecryption(encBuf, keyBuf, macKeyBuf, ivBuf, encrypted_hash, plaintext_hash) {
  console.log('Starting decryption process...');
  
  if (encBuf.length <= 10) {
    throw new Error('Encrypted payload too small');
  }

  // Verify encrypted hash if provided
  if (encrypted_hash) {
    const encSha = createHash('sha256').update(encBuf).digest('base64');
    console.log('Encrypted SHA256 verification:', encSha === encrypted_hash ? 'PASS' : 'FAIL');
    if (encSha !== encrypted_hash) {
      console.warn('Encrypted hash mismatch, continuing anyway...');
    }
  }

  // Split ciphertext and appended MAC (last 10 bytes)
  const macTrailer = encBuf.subarray(encBuf.length - 10);
  const cipherText = encBuf.subarray(0, encBuf.length - 10);

  console.log(`Ciphertext length: ${cipherText.length}, MAC trailer length: ${macTrailer.length}`);

  // HMAC-SHA256(iv || ciphertext), compare first 10 bytes
  const macFull = createHmac('sha256', macKeyBuf).update(ivBuf).update(cipherText).digest();
  const mac10 = macFull.subarray(0, 10);

  if (!mac10.equals(macTrailer)) {
    throw new Error('HMAC verification failed');
  }
  console.log('✅ HMAC verification passed');

  if (cipherText.length % 16 !== 0) {
    throw new Error(`Ciphertext length not a multiple of 16: ${cipherText.length}`);
  }

  // Decrypt AES-256-CBC with PKCS#7 padding
  let decrypted;
  try {
    const decipher = createDecipheriv('aes-256-cbc', keyBuf, ivBuf);
    decipher.setAutoPadding(true);
    decrypted = Buffer.concat([decipher.update(cipherText), decipher.final()]);
    console.log('✅ AES decryption successful');
  } catch (e) {
    throw new Error(`AES decryption failed: ${e.message}`);
  }

  // Verify plaintext hash if provided
  if (plaintext_hash) {
    const plainSha = createHash('sha256').update(decrypted).digest('base64');
    console.log('Plaintext SHA256 verification:', plainSha === plaintext_hash ? 'PASS' : 'FAIL');
    if (plainSha !== plaintext_hash) {
      console.warn('Plaintext hash mismatch, but decryption completed');
    }
  }

  console.log(`✅ Decryption successful. Decrypted size: ${decrypted.length} bytes`);
  return decrypted;
}

// WhatsApp Image Decryption with enhanced error handling and fallbacks
async function decryptWhatsAppImage(imageData) {
  console.log('=== DECRYPT WHATSAPP IMAGE (CBC+HMAC-10) ===');
  console.log('Image data keys:', Object.keys(imageData));

  try {
    const { cdn_url, encryption_metadata } = imageData;
    if (!cdn_url || !encryption_metadata) {
      throw new Error('Missing cdn_url or encryption_metadata');
    }

    const { encryption_key, hmac_key, iv, encrypted_hash, plaintext_hash } = encryption_metadata;
    console.log('Encryption metadata keys:', Object.keys(encryption_metadata));

    // Validate encryption keys
    const keyBuf = Buffer.from(encryption_key, 'base64');
    const macKeyBuf = Buffer.from(hmac_key, 'base64');
    const ivBuf = Buffer.from(iv, 'base64');

    if (keyBuf.length !== 32) throw new Error(`Invalid encryption_key length: ${keyBuf.length}, expected 32`);
    if (macKeyBuf.length !== 32) throw new Error(`Invalid hmac_key length: ${macKeyBuf.length}, expected 32`);
    if (ivBuf.length !== 16) throw new Error(`Invalid iv length: ${ivBuf.length}, expected 16`);

    console.log('✅ Encryption keys validated');
    console.log('Attempting to fetch encrypted image from CDN:', cdn_url);
    
    // Fetch with enhanced error handling
    const encBuf = await fetchWithTimeoutAndRetry(cdn_url, {
      timeout: FETCH_TIMEOUT,
      retries: FETCH_RETRIES,
      retryDelay: RETRY_DELAY
    });
    
    console.log(`✅ Encrypted image fetched successfully, size: ${encBuf.byteLength} bytes`);

    // Perform decryption
    const decrypted = await performImageDecryption(
      encBuf, keyBuf, macKeyBuf, ivBuf, encrypted_hash, plaintext_hash
    );

    return decrypted.toString('base64');

  } catch (error) {
    console.error('❌ WhatsApp image decryption failed:', error.message);
    console.error('Error stack:', error.stack);
    throw new Error(`Image decryption failed: ${error.message}`);
  }
}

// Fallback function for image processing failures
async function decryptWhatsAppImageWithFallback(imageData) {
  try {
    console.log('🔄 Attempting primary decryption method...');
    return await decryptWhatsAppImage(imageData);
  } catch (primaryError) {
    console.error('❌ Primary decryption failed:', primaryError.message);
    
    const { cdn_url } = imageData;
    
    // Fallback 1: Try with different headers
    try {
      console.log('🔄 Fallback 1: Trying with alternative headers...');
      const response = await fetch(cdn_url, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
          'Referer': 'https://web.whatsapp.com/',
          'Origin': 'https://web.whatsapp.com',
          'Sec-Fetch-Dest': 'image',
          'Sec-Fetch-Mode': 'cors',
          'Sec-Fetch-Site': 'cross-site'
        },
        mode: 'cors'
      });
      
      if (response.ok) {
        const buffer = Buffer.from(await response.arrayBuffer());
        console.log('✅ Alternative headers worked, reattempting decryption...');
        
        // Try decryption again with the newly fetched data
        const { encryption_metadata } = imageData;
        const { encryption_key, hmac_key, iv, encrypted_hash, plaintext_hash } = encryption_metadata;
        
        const keyBuf = Buffer.from(encryption_key, 'base64');
        const macKeyBuf = Buffer.from(hmac_key, 'base64');
        const ivBuf = Buffer.from(iv, 'base64');
        
        const decrypted = await performImageDecryption(
          buffer, keyBuf, macKeyBuf, ivBuf, encrypted_hash, plaintext_hash
        );
        
        return decrypted.toString('base64');
      }
    } catch (fallbackError) {
      console.error('❌ Fallback 1 failed:', fallbackError.message);
    }
    
    // Fallback 2: Try without encryption if URL seems to be direct
    try {
      console.log('🔄 Fallback 2: Attempting direct fetch (maybe unencrypted)...');
      const directResponse = await fetchWithTimeoutAndRetry(cdn_url, {
        timeout: 15000, // Shorter timeout for fallback
        retries: 2
      });
      
      // Check if this looks like a valid image
      const firstBytes = directResponse.subarray(0, 4);
      const isJPEG = firstBytes[0] === 0xFF && firstBytes[1] === 0xD8;
      const isPNG = firstBytes[0] === 0x89 && firstBytes[1] === 0x50 && firstBytes[2] === 0x4E && firstBytes[3] === 0x47;
      
      if (isJPEG || isPNG) {
        console.log('✅ Fallback 2: Direct image detected (unencrypted)');
        return directResponse.toString('base64');
      }
    } catch (directError) {
      console.error('❌ Fallback 2 failed:', directError.message);
    }
    
    // All fallbacks failed
    throw new Error(`All decryption methods failed. Primary error: ${primaryError.message}`);
  }
}

// Upload to Supabase Storage via S3-compatible API (SigV4)
async function uploadGeneratedImageToSupabase(base64Data, mimeType) {
  const supabaseUrl = process.env.SUPABASE_URL;
  const s3Endpoint = process.env.SUPABASE_S3_ENDPOINT;
  const s3Region = process.env.SUPABASE_S3_REGION || 'us-east-1';
  const accessKeyId = process.env.SUPABASE_S3_ACCESS_KEY_ID;
  const secretAccessKey = process.env.SUPABASE_S3_SECRET_ACCESS_KEY;
  const bucket = process.env.SUPABASE_S3_BUCKET || 'generated-images';

  if (!supabaseUrl || !s3Endpoint || !accessKeyId || !secretAccessKey) {
    throw new Error('Missing SUPABASE_URL, SUPABASE_S3_ENDPOINT, or S3 credentials');
  }

  const buffer = Buffer.from(base64Data, 'base64');
  const ext = (mimeType && mimeType.split('/')[1]) || 'jpg';
  const filename = `generated-${Date.now()}-${Math.random().toString(36).substring(7)}.${ext}`;

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

async function sendWhatsAppTextMessage(toE164, message) {
  if (!toE164) throw new Error('Missing recipient phone number (E.164 format)');
  if (!message) throw new Error('Missing message text');

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
      type: 'text',
      text: { body: message }
    })
  });

  const data = await resp.json();
  if (!resp.ok) {
    throw new Error(`WhatsApp send failed ${resp.status}: ${JSON.stringify(data)}`);
  }
  return data;
}

// Enhanced async background processing with better error handling
async function processImageGenerationAsync(productImage, productCategory, sceneDescription, priceOverlay, userPhone) {
  console.log('🚀 Starting async image generation...');
  console.log('Input parameters:', {
    productImageType: Array.isArray(productImage) ? 'array' : typeof productImage,
    productImageLength: Array.isArray(productImage) ? productImage.length : 'N/A',
    productCategory,
    sceneDescription,
    priceOverlay,
    userPhone
  });
  
  try {
    // Process image data asynchronously
    console.log('=== ASYNC IMAGE PROCESSING ===');
    let actualImageData;
    
    if (Array.isArray(productImage) && productImage.length > 0) {
      console.log('Processing WhatsApp image array');
      const firstImage = productImage[0];
      console.log('First image keys:', Object.keys(firstImage));
      
      if (firstImage.encryption_metadata) {
        console.log('🔐 Decrypting WhatsApp encrypted image...');
        
        try {
          // Try primary decryption method with enhanced error handling
          actualImageData = await decryptWhatsAppImageWithFallback(firstImage);
          console.log('✅ Image decryption completed successfully');
        } catch (decryptError) {
          console.error('❌ All decryption methods failed:', decryptError.message);
          
          // Send detailed error message to user
          if (userPhone) {
            await sendWhatsAppTextMessage(
              userPhone, 
              "⚠️ Sorry, we couldn't process your encrypted image. This might be due to:\n" +
              "• Network connectivity issues\n" +
              "• Expired image link\n" +
              "• Unsupported encryption format\n\n" +
              "Please try uploading the image again or use a different image."
            );
          }
          return;
        }
      } else if (firstImage.cdn_url) {
        console.log('📥 Fetching unencrypted image from CDN...');
        try {
          const buffer = await fetchWithTimeoutAndRetry(firstImage.cdn_url, {
            timeout: FETCH_TIMEOUT,
            retries: FETCH_RETRIES,
            retryDelay: RETRY_DELAY
          });
          actualImageData = buffer.toString('base64');
          console.log('✅ Unencrypted image fetch completed');
        } catch (fetchError) {
          console.error('❌ Image fetch failed:', fetchError.message);
          if (userPhone) {
            await sendWhatsAppTextMessage(
              userPhone, 
              "⚠️ Sorry, we couldn't download your image. This might be due to:\n" +
              "• Network connectivity issues\n" +
              "• Expired image link\n" +
              "• Server temporarily unavailable\n\n" +
              "Please try again in a few moments."
            );
          }
          return;
        }
      } else {
        console.error('❌ Invalid image format - missing both cdn_url and encryption_metadata');
        if (userPhone) {
          await sendWhatsAppTextMessage(
            userPhone, 
            "⚠️ Invalid image format received. Please make sure you're uploading a valid image file."
          );
        }
        return;
      }
    } else if (typeof productImage === 'string') {
      console.log('📝 Processing direct base64 string...');
      actualImageData = productImage;
    } else {
      console.error('❌ Invalid product_image format - expected array or string');
      if (userPhone) {
        await sendWhatsAppTextMessage(
          userPhone, 
          "⚠️ Invalid image format. Please upload a valid image file."
        );
      }
      return;
    }
    
    console.log('✅ Async image processing successful');
    console.log(`Image data size: ${actualImageData.length} characters`);

    console.log('🤖 Starting AI image generation...');
    
    // Add progress message to user
    if (userPhone) {
      try {
        await sendWhatsAppTextMessage(
          userPhone, 
          "🎨 Creating your professional product image... This may take a few moments."
        );
      } catch (progressError) {
        console.warn('Could not send progress message:', progressError.message);
      }
    }

    const imageUrl = await generateImageFromAi(
      actualImageData,
      productCategory.trim(),
      sceneDescription && sceneDescription.trim() ? sceneDescription.trim() : null,
      priceOverlay && priceOverlay.trim() ? priceOverlay.trim() : null
    );
    
    console.log('✅ Async image generation successful:', imageUrl);

    // Send ONLY the final generated image to user
    if (userPhone) {
      console.log('📱 Sending generated image to user:', userPhone);
      const caption = (priceOverlay && priceOverlay.trim())
        ? `🎉 Here's your professional ${productCategory.trim()} photo — ${priceOverlay.trim()}`
        : `🎉 Here's your professional ${productCategory.trim()} photo!`;
      
      try {
        await sendWhatsAppImageMessage(userPhone, imageUrl, caption);
        console.log('✅ Generated image sent to user via WhatsApp');
        
        // Send a follow-up message with tips
        await sendWhatsAppTextMessage(
          userPhone,
          "💡 Tips for best results:\n" +
          "• Use high-quality product images\n" +
          "• Describe your desired scene clearly\n" +
          "• Try different categories for variety\n\n" +
          "Send another image to create more!"
        );
      } catch (sendError) {
        console.error('❌ Failed to send generated image:', sendError.message);
        
        // Fallback: send the URL as text if image sending fails
        try {
          await sendWhatsAppTextMessage(
            userPhone,
            `🎉 Your ${productCategory.trim()} image is ready!\n\nView it here: ${imageUrl}`
          );
        } catch (fallbackError) {
          console.error('❌ Even fallback message failed:', fallbackError.message);
        }
      }
    }

  } catch (error) {
    console.error('❌ Async image generation failed:', error);
    console.error('Error stack:', error.stack);
    
    // Send helpful error message to user instead of silent failure
    if (userPhone) {
      try {
        let errorMessage = "⚠️ Sorry, we encountered an issue generating your image. ";
        
        // Provide specific error guidance based on error type
        if (error.message.includes('Gemini')) {
          errorMessage += "Our AI service is temporarily unavailable. Please try again in a few minutes.";
        } else if (error.message.includes('timeout')) {
          errorMessage += "The request timed out. Please try again with a smaller image.";
        } else if (error.message.includes('network') || error.message.includes('fetch')) {
          errorMessage += "Network connectivity issue. Please check your connection and try again.";
        } else {
          errorMessage += "Please try again with a different image or contact support if the issue persists.";
        }
        
        await sendWhatsAppTextMessage(userPhone, errorMessage);
      } catch (sendError) {
        console.error('❌ Failed to send error message to user:', sendError);
      }
    }
  }
}

// --- Request Handlers ---
async function handleDataExchange(decryptedBody) {
  const { action, screen, data } = decryptedBody;
  console.log(`Processing action: ${action} for screen: ${screen}`);
  console.log('Data received:', JSON.stringify(data, null, 2));

  if (action === 'INIT') {
    return { screen: 'COLLECT_INFO', data: {} };
  }

  if (action === 'data_exchange') {
    console.log('=== DATA EXCHANGE ACTION ===');

    if (data && typeof data === 'object') {
      const { scene_description, price_overlay, product_image, product_category, mobile_number } = data;

      console.log('=== FIELD VALIDATION ===');
      console.log('product_image:', product_image ? 'present' : 'MISSING (REQUIRED)');
      console.log('product_category:', product_category ? `"${product_category}"` : 'MISSING (REQUIRED)');
      console.log('scene_description:', scene_description ? `"${scene_description}"` : 'not provided (optional)');
      console.log('price_overlay:', price_overlay ? `"${price_overlay}"` : 'not provided (optional)');
      console.log('mobile_number:', mobile_number ? `"${mobile_number}"` : 'not provided');

      // Enhanced validation with better error messages
      if (!product_image) {
        return {
          screen: 'COLLECT_INFO',
          data: { 
            error_message: "📸 Product image is required. Please upload a clear photo of your product to get started." 
          }
        };
      }

      if (!product_category || !product_category.trim()) {
        return {
          screen: 'COLLECT_INFO',
          data: { 
            error_message: "🏷️ Product category is required. Please specify what type of product this is (e.g., 'smartphone', 'shoes', 'watch', etc.)." 
          }
        };
      }

      // Validate product category length and content
      if (product_category.trim().length < 2) {
        return {
          screen: 'COLLECT_INFO',
          data: { 
            error_message: "🏷️ Product category is too short. Please provide a more descriptive category (e.g., 'laptop', 'dress', 'coffee mug')." 
          }
        };
      }

      // GET USER PHONE FOR ASYNC MESSAGING
      const userPhone = getUserPhoneFromPayload(decryptedBody) || mobile_number;
      console.log('User phone for async messaging:', userPhone);

      if (!userPhone) {
        console.warn('⚠️ No user phone found for async messaging');
      }

      // IMMEDIATELY RETURN SUCCESS AND START ASYNC PROCESSING
      console.log('🚀 Starting async image generation process...');
      
      // Don't await this - let it run in background with all the data
      processImageGenerationAsync(
        product_image, // Pass raw image data to async function
        product_category,
        scene_description,
        price_overlay,
        userPhone
      ).catch(error => {
        console.error('Background processing error:', error);
      });

      // Return success immediately with status message
      return { 
        screen: 'SUCCESS_SCREEN', 
        data: { 
          image_url: 'https://via.placeholder.com/400x400/4CAF50/white?text=Generating...', // Placeholder
          status: 'processing',
          message: `🎨 Creating your professional ${product_category.trim()} photo! You'll receive it via WhatsApp shortly.`,
          processing_details: {
            category: product_category.trim(),
            has_scene: !!(sceneDescription && sceneDescription.trim()),
            has_price: !!(priceOverlay && priceOverlay.trim())
          }
        } 
      };

    } else {
      return { 
        screen: 'COLLECT_INFO', 
        data: { 
          error_message: '📝 No data received. Please fill in the required information and try again.' 
        } 
      };
    }
  }

  if (action === 'BACK') {
    if (screen === 'COLLECT_IMAGE_SCENE') {
      return { screen: 'COLLECT_INFO', data: {} };
    }
    return { screen: 'COLLECT_INFO', data: {} };
  }

  console.log(`Unhandled action/screen combination: ${action}/${screen}`);
  return { 
    screen: 'COLLECT_INFO', 
    data: { 
      error_message: '⚠️ An unexpected error occurred. Please try again.' 
    } 
  };
}

async function handleHealthCheck() {
  return { 
    data: { 
      status: 'active',
      timestamp: new Date().toISOString(),
      version: '2.0.0',
      features: ['image_generation', 'whatsapp_integration', 'enhanced_error_handling']
    } 
  };
}

async function handleErrorNotification(decryptedBody) {
  console.log('Error notification received:', JSON.stringify(decryptedBody, null, 2));
  return { 
    data: { 
      acknowledged: true,
      timestamp: new Date().toISOString()
    } 
  };
}

// --- Main Vercel API Handler ---
export default async function handler(req, res) {
  const startTime = Date.now();
  console.log(`\n🚀 === REQUEST START: ${req.method} ${req.url} ===`);
  
  // Handle CORS
  if (req.method === 'OPTIONS') {
    console.log('Handling CORS preflight request');
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
    console.log('🔧 Validating environment variables...');
    validateEnvironmentVars();
    console.log('✅ Environment validation passed');
  } catch (error) {
    console.error('❌ Environment validation failed:', error.message);
    return res.status(500).json({ 
      error: 'Internal Server Error',
      details: 'Configuration issue'
    });
  }

  if (req.method === 'GET') {
    console.log('📥 Handling GET request (webhook verification)');
    const { query } = req;
    const mode = query['hub.mode'];
    const token = query['hub.verify_token'];
    const challenge = query['hub.challenge'];
    const verifyToken = process.env.VERIFY_TOKEN;

    console.log('Webhook verification:', { mode, token: token ? '***' : 'missing', challenge: challenge ? 'present' : 'missing' });

    if (mode === 'subscribe' && token === verifyToken && challenge) {
      console.log('✅ Webhook verification successful');
      res.setHeader('Content-Type', 'text/plain');
      return res.status(200).send(challenge);
    } else {
      console.log('❌ Webhook verification failed');
      return res.status(403).json({ error: 'Forbidden' });
    }
  }

  if (req.method === 'POST') {
    try {
      console.log('📥 Handling POST request (encrypted flow data)');
      const requestBody = req.body;
      
      if (!requestBody) {
        throw new Error('Empty request body');
      }

      console.log('🔐 Importing private key and decrypting request...');
      const privateKeyPem = process.env.PRIVATE_KEY;
      const privateKey = await importPrivateKey(privateKeyPem);

      const { decryptedBody, aesKeyBuffer, initialVectorBuffer } = await decryptRequest(requestBody, privateKey);
      console.log('✅ Request decrypted successfully');
      console.log('Decrypted body action:', decryptedBody.action);

      let responsePayload;
      
      if (decryptedBody.action === 'ping') {
        console.log('🏥 Handling health check');
        responsePayload = await handleHealthCheck();
      } else if (decryptedBody.action === 'error_notification') {
        console.log('⚠️ Handling error notification');
        responsePayload = await handleErrorNotification(decryptedBody);
      } else {
        console.log('💼 Handling data exchange');
        responsePayload = await handleDataExchange(decryptedBody);
      }

      console.log('🔐 Encrypting response...');
      const encryptedResponse = await encryptResponse(responsePayload, aesKeyBuffer, initialVectorBuffer);
      console.log('✅ Response encrypted successfully');

      const processingTime = Date.now() - startTime;
      console.log(`⏱️ Total processing time: ${processingTime}ms`);

      res.setHeader('Content-Type', 'application/json');
      console.log('📤 Sending encrypted response');
      return res.status(200).send(encryptedResponse);
      
    } catch (error) {
      console.error('❌ Error processing POST request:', error);
      console.error('Error stack:', error.stack);
      
      const processingTime = Date.now() - startTime;
      console.log(`⏱️ Failed after: ${processingTime}ms`);
      
      return res.status(500).json({ 
        error: 'Internal Server Error',
        message: error.message,
        timestamp: new Date().toISOString()
      });
    }
  }

  console.log(`❌ Method ${req.method} not allowed`);
  return res.status(405).json({ 
    error: 'Method Not Allowed',
    allowed: ['GET', 'POST', 'OPTIONS']
  });
}
