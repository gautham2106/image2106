// api/webhook.js - Fixed Vercel WhatsApp Flow Handler
import { createHash, createHmac, createDecipheriv } from 'crypto';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';

// --- Environment Validation ---
function validateEnvironmentVars() {
  const required = [
    'PRIVATE_KEY',
    'VERIFY_TOKEN', 
    'GEMINI_API_KEY',
    'WHATSAPP_TOKEN',
    'WHATSAPP_PHONE_NUMBER_ID'
  ];
  
  const missing = required.filter(v => !process.env[v]);
  if (missing.length > 0) {
    throw new Error(`Missing: ${missing.join(', ')}`);
  }
}

// --- Crypto Utilities ---
async function importPrivateKey(privateKeyPem) {
  const { webcrypto } = await import('crypto');
  
  const pemHeader = "-----BEGIN PRIVATE KEY-----";
  const pemFooter = "-----END PRIVATE KEY-----";
  const pemContents = privateKeyPem
    .replace(pemHeader, "")
    .replace(pemFooter, "")
    .replace(/\s/g, "");
    
  const binaryDer = Uint8Array.from(Buffer.from(pemContents, 'base64'));
  
  return await webcrypto.subtle.importKey(
    "pkcs8", 
    binaryDer, 
    { name: "RSA-OAEP", hash: "SHA-256" }, 
    false, 
    ["decrypt"]
  );
}

async function decryptRequest(body, privateKey) {
  const { webcrypto } = await import('crypto');
  
  const { encrypted_aes_key, encrypted_flow_data, initial_vector } = body;
  
  if (!encrypted_aes_key || !encrypted_flow_data || !initial_vector) {
    throw new Error('Missing encryption fields');
  }

  // Decrypt AES key with RSA
  const encryptedAesKeyBuffer = Buffer.from(encrypted_aes_key, 'base64');
  const aesKeyBuffer = new Uint8Array(
    await webcrypto.subtle.decrypt(
      { name: "RSA-OAEP" }, 
      privateKey, 
      encryptedAesKeyBuffer
    )
  );

  // Decrypt flow data with AES-GCM
  const flowDataBuffer = Buffer.from(encrypted_flow_data, 'base64');
  const initialVectorBuffer = Buffer.from(initial_vector, 'base64');

  const aesKey = await webcrypto.subtle.importKey(
    "raw", 
    aesKeyBuffer, 
    { name: "AES-GCM" }, 
    false, 
    ["decrypt"]
  );

  const decryptedBuffer = await webcrypto.subtle.decrypt(
    { name: "AES-GCM", iv: initialVectorBuffer, tagLength: 128 },
    aesKey,
    flowDataBuffer
  );

  const decryptedBody = JSON.parse(new TextDecoder().decode(decryptedBuffer));

  return { decryptedBody, aesKeyBuffer, initialVectorBuffer };
}

async function encryptResponse(response, aesKeyBuffer, initialVectorBuffer) {
  const { webcrypto } = await import('crypto');
  
  // Flip IV bits for response
  const flippedIv = new Uint8Array(initialVectorBuffer.map(byte => ~byte & 0xFF));

  const aesKey = await webcrypto.subtle.importKey(
    "raw", 
    aesKeyBuffer, 
    { name: "AES-GCM" }, 
    false, 
    ["encrypt"]
  );

  const responseBuffer = new TextEncoder().encode(JSON.stringify(response));
  
  const encryptedBuffer = await webcrypto.subtle.encrypt(
    { name: "AES-GCM", iv: flippedIv, tagLength: 128 },
    aesKey,
    responseBuffer
  );

  return Buffer.from(new Uint8Array(encryptedBuffer)).toString('base64');
}

// --- WhatsApp Image Decryption ---
async function decryptWhatsAppImage(imageData) {
  console.log('Decrypting WhatsApp image...');
  
  const { cdn_url, encryption_metadata } = imageData;
  if (!cdn_url || !encryption_metadata) {
    throw new Error('Missing CDN URL or encryption metadata');
  }

  const { encryption_key, hmac_key, iv } = encryption_metadata;
  
  const keyBuf = Buffer.from(encryption_key, 'base64');
  const macKeyBuf = Buffer.from(hmac_key, 'base64'); 
  const ivBuf = Buffer.from(iv, 'base64');

  // Fetch encrypted image
  const response = await fetch(cdn_url);
  if (!response.ok) {
    throw new Error(`Failed to fetch image: ${response.status}`);
  }
  
  const encBuf = Buffer.from(await response.arrayBuffer());
  
  if (encBuf.length <= 10) {
    throw new Error('Encrypted payload too small');
  }

  // Split ciphertext and MAC (last 10 bytes)
  const macTrailer = encBuf.subarray(-10);
  const cipherText = encBuf.subarray(0, -10);

  // Verify HMAC
  const macFull = createHmac('sha256', macKeyBuf)
    .update(ivBuf)
    .update(cipherText)
    .digest();
    
  if (!macFull.subarray(0, 10).equals(macTrailer)) {
    throw new Error('HMAC verification failed');
  }

  // Decrypt with AES-256-CBC
  const decipher = createDecipheriv('aes-256-cbc', keyBuf, ivBuf);
  decipher.setAutoPadding(true);
  const decrypted = Buffer.concat([
    decipher.update(cipherText), 
    decipher.final()
  ]);

  console.log('Image decrypted successfully');
  return decrypted.toString('base64');
}

// --- AI Image Generation ---
async function generateImageWithGemini(productImageBase64, productCategory, sceneDescription, priceOverlay) {
  console.log('Generating image with Gemini...');
  
  const apiKey = process.env.GEMINI_API_KEY;
  
  // Clean base64 data
  let cleanBase64 = productImageBase64;
  if (productImageBase64.startsWith('data:')) {
    const commaIndex = productImageBase64.indexOf(',');
    if (commaIndex !== -1) {
      cleanBase64 = productImageBase64.substring(commaIndex + 1);
    }
  }

  // Create prompt
  let prompt = `Create a professional product photo of this ${productCategory}.`;
  
  if (sceneDescription?.trim()) {
    prompt += ` Setting: ${sceneDescription}.`;
  } else {
    prompt += ` Use a clean, professional background.`;
  }
  
  if (priceOverlay?.trim()) {
    prompt += ` Include the price "${priceOverlay}" as a stylish overlay.`;
  }
  
  prompt += ` Make it look like a high-quality commercial product photo.`;

  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`;
  
  const requestBody = {
    contents: [{
      parts: [
        { text: prompt },
        {
          inlineData: {
            mimeType: "image/jpeg",
            data: cleanBase64
          }
        }
      ]
    }],
    generationConfig: {
      temperature: 0.7,
      maxOutputTokens: 1024,
      topP: 0.9
    }
  };

  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(requestBody)
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Gemini API failed: ${errorText}`);
  }

  const data = await response.json();
  const candidate = data?.candidates?.[0];
  
  if (!candidate?.content?.parts) {
    throw new Error('No response from Gemini');
  }

  // Find generated image
  for (const part of candidate.content.parts) {
    if (part.inlineData) {
      const { mimeType, data: imageData } = part.inlineData;
      console.log('Image generated successfully');
      
      // Try to upload to Supabase, fallback to data URL
      try {
        if (process.env.SUPABASE_URL && process.env.SUPABASE_S3_ENDPOINT) {
          return await uploadToSupabase(imageData, mimeType);
        }
      } catch (uploadError) {
        console.warn('Upload failed, using data URL:', uploadError);
      }
      
      return `data:${mimeType};base64,${imageData}`;
    }
  }

  throw new Error('No image generated');
}

// --- Supabase Upload (Optional) ---
async function uploadToSupabase(base64Data, mimeType) {
  const supabaseUrl = process.env.SUPABASE_URL;
  const s3Endpoint = process.env.SUPABASE_S3_ENDPOINT;
  const accessKeyId = process.env.SUPABASE_S3_ACCESS_KEY_ID;
  const secretAccessKey = process.env.SUPABASE_S3_SECRET_ACCESS_KEY;
  const bucket = process.env.SUPABASE_S3_BUCKET || 'generated-images';
  
  if (!supabaseUrl || !s3Endpoint || !accessKeyId || !secretAccessKey) {
    throw new Error('Missing Supabase config');
  }

  const buffer = Buffer.from(base64Data, 'base64');
  const ext = mimeType?.split('/')[1] || 'jpg';
  const filename = `generated-${Date.now()}.${ext}`;

  const s3 = new S3Client({
    region: 'us-east-1',
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

  const publicUrl = `${supabaseUrl.replace(/\/+$/, '')}/storage/v1/object/public/${bucket}/${filename}`;
  console.log('Uploaded to Supabase:', publicUrl);
  return publicUrl;
}

// --- WhatsApp Messaging ---
function getUserPhone(decryptedBody) {
  const candidates = [
    decryptedBody?.user?.wa_id,
    decryptedBody?.user?.phone,
    decryptedBody?.phone_number,
    decryptedBody?.mobile_number,
    decryptedBody?.data?.phone_number,
    decryptedBody?.data?.mobile_number
  ];

  const raw = candidates.find(v => typeof v === 'string' && v.trim());
  if (!raw) return null;

  const digits = raw.replace(/\D/g, '');
  if (!digits) return null;

  // Add country code for 10-digit numbers (assuming India)
  return digits.length === 10 ? `91${digits}` : digits;
}

async function sendWhatsAppImage(toE164, imageUrl, caption) {
  if (!toE164 || !imageUrl) {
    throw new Error('Missing phone number or image URL');
  }

  const url = `https://graph.facebook.com/v21.0/${process.env.WHATSAPP_PHONE_NUMBER_ID}/messages`;

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${process.env.WHATSAPP_TOKEN}`,
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

  const data = await response.json();
  
  if (!response.ok) {
    throw new Error(`WhatsApp send failed: ${JSON.stringify(data)}`);
  }
  
  console.log('WhatsApp message sent:', data);
  return data;
}

// --- Flow Handlers ---
async function handleDataExchange(decryptedBody) {
  const { action, screen, data } = decryptedBody;
  
  console.log(`Action: ${action}, Screen: ${screen}`);
  console.log('Data:', JSON.stringify(data, null, 2));

  if (action === 'INIT') {
    return { screen: 'COLLECT_INFO', data: {} };
  }

  if (action === 'data_exchange') {
    if (!data || typeof data !== 'object') {
      return { 
        screen: 'COLLECT_INFO', 
        data: { error_message: 'Please fill in the form.' } 
      };
    }

    const { product_image, product_category } = data;

    // Validate required fields
    if (!product_image) {
      return {
        screen: 'COLLECT_IMAGE_SCENE',
        data: { error_message: 'Product image is required.' }
      };
    }

    if (!product_category?.trim()) {
      return {
        screen: 'COLLECT_INFO',
        data: { error_message: 'Product category is required.' }
      };
    }

    // Navigate to success screen
    return { screen: 'SUCCESS_SCREEN', data: {} };
  }

  if (action === 'BACK') {
    return screen === 'COLLECT_IMAGE_SCENE' 
      ? { screen: 'COLLECT_INFO', data: {} }
      : { screen: 'COLLECT_INFO', data: {} };
  }

  return { screen: 'COLLECT_INFO', data: {} };
}

async function handleComplete(decryptedBody) {
  console.log('=== COMPLETE ACTION ===');
  
  const { data } = decryptedBody;
  if (!data) {
    console.log('No data in complete action');
    return { status: 'success' };
  }

  const { mobile_number, product_category, scene_description, price_overlay, product_image } = data;
  
  console.log('Complete data:', {
    mobile_number: mobile_number || 'missing',
    product_category: product_category || 'missing',
    scene_description: scene_description || 'none',
    price_overlay: price_overlay || 'none',
    product_image: Array.isArray(product_image) ? `array[${product_image.length}]` : typeof product_image
  });

  // Get phone number
  const userPhone = getUserPhone(decryptedBody) || 
                   (mobile_number ? mobile_number.replace(/\D/g, '') : null);
  
  if (!userPhone) {
    console.warn('No phone number found');
    return { status: 'success' };
  }

  const toPhone = userPhone.length === 10 ? `91${userPhone}` : userPhone;

  try {
    // Process product image
    let imageBase64;
    
    if (Array.isArray(product_image) && product_image.length > 0) {
      const firstImage = product_image[0];
      
      if (firstImage.encryption_metadata) {
        imageBase64 = await decryptWhatsAppImage(firstImage);
      } else if (firstImage.cdn_url) {
        const response = await fetch(firstImage.cdn_url);
        if (!response.ok) throw new Error(`Failed to fetch: ${response.status}`);
        const buffer = await response.arrayBuffer();
        imageBase64 = Buffer.from(buffer).toString('base64');
      } else {
        throw new Error('Invalid image format');
      }
    } else if (typeof product_image === 'string') {
      imageBase64 = product_image;
    } else {
      throw new Error('No valid product image');
    }

    // Generate AI image
    const generatedImageUrl = await generateImageWithGemini(
      imageBase64,
      product_category || 'Product',
      scene_description,
      price_overlay
    );

    // Send via WhatsApp
    const caption = price_overlay?.trim() 
      ? `${product_category || 'Product'} — ${price_overlay}`
      : product_category || 'Your generated product image';

    await sendWhatsAppImage(toPhone, generatedImageUrl, caption);
    
    console.log('✅ Complete action successful');

  } catch (error) {
    console.error('❌ Complete action error:', error);
  }

  return { status: 'success' };
}

// --- Main Handler ---
export default async function handler(req, res) {
  // CORS headers
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
  };

  Object.entries(corsHeaders).forEach(([key, value]) => {
    res.setHeader(key, value);
  });

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Validate environment
  try {
    validateEnvironmentVars();
  } catch (error) {
    console.error('Environment validation failed:', error.message);
    return res.status(500).json({ error: 'Server configuration error' });
  }

  // GET - Webhook verification
  if (req.method === 'GET') {
    const { query } = req;
    const mode = query['hub.mode'];
    const token = query['hub.verify_token'];
    const challenge = query['hub.challenge'];

    if (mode === 'subscribe' && token === process.env.VERIFY_TOKEN && challenge) {
      console.log('Webhook verified successfully');
      res.setHeader('Content-Type', 'text/plain');
      return res.status(200).send(challenge);
    }
    
    console.log('Webhook verification failed');
    return res.status(403).json({ error: 'Forbidden' });
  }

  // POST - Handle flow requests
  if (req.method === 'POST') {
    console.log('=== INCOMING POST REQUEST ===');
    console.log('Body type:', typeof req.body);
    console.log('Body keys:', Object.keys(req.body || {}));
    
    try {
      const requestBody = req.body;
      
      // Import private key and decrypt
      const privateKeyPem = process.env.PRIVATE_KEY;
      const privateKey = await importPrivateKey(privateKeyPem);
      
      const { decryptedBody, aesKeyBuffer, initialVectorBuffer } = 
        await decryptRequest(requestBody, privateKey);

      console.log('Decrypted action:', decryptedBody.action);

      // Handle different actions
      let responsePayload;
      
      switch (decryptedBody.action) {
        case 'ping':
          responsePayload = { data: { status: 'active' } };
          break;
          
        case 'error_notification':
          console.log('Error notification:', decryptedBody);
          responsePayload = { data: { acknowledged: true } };
          break;
          
        case 'complete':
          responsePayload = await handleComplete(decryptedBody);
          break;
          
        default:
          responsePayload = await handleDataExchange(decryptedBody);
      }

      // Encrypt and send response
      const encryptedResponse = await encryptResponse(
        responsePayload, 
        aesKeyBuffer, 
        initialVectorBuffer
      );

      res.setHeader('Content-Type', 'application/json');
      return res.status(200).send(encryptedResponse);

    } catch (error) {
      console.error('❌ Request processing error:', error);
      return res.status(500).json({ 
        error: 'Internal Server Error',
        details: error.message 
      });
    }
  }

  return res.status(405).json({ error: 'Method Not Allowed' });
}
