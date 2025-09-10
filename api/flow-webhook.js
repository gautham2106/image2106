// Vercel Node.js API Route for WhatsApp Flow with Gemini AI + BSP Lead Capture
// Place this file at: api/flow-webhook.js

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

// --- BSP Lead Storage ---
// Simple in-memory storage for BSP leads (resets on server restart)
const bspLeadStore = {
  latest: null,           // Most recent lead
  byPhone: new Map(),     // Map phone -> lead data
  bySession: new Map(),   // Map session/chat_id -> phone
  recent: []              // Array of recent leads (max 100)
};

// Store BSP lead data
function storeBspLead(leadData) {
  const phoneNumber = leadData.phoneNumber || leadData.chat_id;
  const timestamp = new Date().toISOString();
  
  const enrichedLead = {
    ...leadData,
    phoneNumber,
    timestamp,
    id: `${phoneNumber}-${Date.now()}`
  };
  
  // Store as latest
  bspLeadStore.latest = enrichedLead;
  
  // Store by phone number
  if (phoneNumber) {
    bspLeadStore.byPhone.set(phoneNumber, enrichedLead);
    
    // Store session mapping
    if (leadData.chatId || leadData.chat_id) {
      bspLeadStore.bySession.set(leadData.chatId || leadData.chat_id, phoneNumber);
    }
  }
  
  // Add to recent leads (keep only last 100)
  bspLeadStore.recent.unshift(enrichedLead);
  if (bspLeadStore.recent.length > 100) {
    bspLeadStore.recent = bspLeadStore.recent.slice(0, 100);
  }
  
  console.log('📍 BSP Lead stored:', {
    phone: phoneNumber,
    name: leadData.firstName || leadData.first_name,
    totalStored: bspLeadStore.byPhone.size,
    recentCount: bspLeadStore.recent.length
  });
  
  return enrichedLead;
}

// Get BSP lead data
function getBspLead(identifier = 'latest') {
  if (identifier === 'latest') {
    return bspLeadStore.latest;
  }
  
  // Try to get by phone number
  if (bspLeadStore.byPhone.has(identifier)) {
    return bspLeadStore.byPhone.get(identifier);
  }
  
  // Try to get by session/chat_id
  if (bspLeadStore.bySession.has(identifier)) {
    const phone = bspLeadStore.bySession.get(identifier);
    return bspLeadStore.byPhone.get(phone);
  }
  
  return null;
}

// Optional: Persist to database (implement based on your needs)
async function persistBspLead(leadData) {
  try {
    // Example: Save to Supabase
    // const { createClient } = require('@supabase/supabase-js');
    // const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
    // await supabase.from('bsp_leads').upsert({
    //   phone_number: leadData.phoneNumber,
    //   first_name: leadData.firstName || leadData.first_name,
    //   email: leadData.email,
    //   chat_id: leadData.chatId || leadData.chat_id,
    //   subscriber_id: leadData.subscriberId,
    //   user_message: leadData.userMessage || leadData.user_message,
    //   postback_id: leadData.postbackId || leadData.postbackid,
    //   created_at: leadData.timestamp
    // });
    
    // Example: Save to Google Sheets
    // await appendToGoogleSheet([
    //   leadData.phoneNumber,
    //   leadData.firstName || leadData.first_name,
    //   leadData.email,
    //   leadData.userMessage || leadData.user_message,
    //   leadData.timestamp
    // ]);
    
    // Example: Send to CRM API
    // await fetch('https://your-crm.com/api/leads', {
    //   method: 'POST',
    //   headers: { 'Content-Type': 'application/json' },
    //   body: JSON.stringify({
    //     phone: leadData.phoneNumber,
    //     name: leadData.firstName || leadData.first_name,
    //     email: leadData.email,
    //     message: leadData.userMessage || leadData.user_message,
    //     timestamp: leadData.timestamp
    //   })
    // });
    
    console.log('💾 BSP lead persistence ready (implement your preferred method)');
    return true;
  } catch (error) {
    console.error('Failed to persist BSP lead:', error);
    return false;
  }
}

// --- BSP Lead Capture Handler ---
async function handleBspLead(req, res) {
  console.log('=== BSP LEAD WEBHOOK ===');
  console.log('Body:', JSON.stringify(req.body, null, 2));
  
  try {
    // Handle both BSP structures:
    // 1. Your planned structure: { phoneNumber, firstName, email, chatId, subscriberId }
    // 2. Current actual structure: { first_name, chat_id, user_message, etc. }
    
    const leadData = {
      phoneNumber: req.body.phoneNumber || req.body.chat_id,
      firstName: req.body.firstName || req.body.first_name,
      email: req.body.email,
      chatId: req.body.chatId || req.body.chat_id,
      subscriberId: req.body.subscriberId,
      userMessage: req.body.user_message,
      postbackId: req.body.postbackid,
      // Include any other fields that might be useful
      ...req.body
    };
    
    console.log('=== EXTRACTED LEAD DATA ===');
    console.log('Phone Number:', leadData.phoneNumber);
    console.log('First Name:', leadData.firstName);
    console.log('Email:', leadData.email);
    console.log('Chat ID:', leadData.chatId);
    console.log('Subscriber ID:', leadData.subscriberId);
    console.log('User Message:', leadData.userMessage);
    console.log('Postback ID:', leadData.postbackId);

    if (leadData.phoneNumber) {
      console.log('✅ LEAD CAPTURED SUCCESSFULLY');
      
      // Store the lead data in memory
      const storedLead = storeBspLead(leadData);
      
      // Optionally persist to database
      await persistBspLead(storedLead);
      
      return res.status(200).json({
        success: true,
        message: 'Lead received and processed',
        data: {
          id: storedLead.id,
          phoneNumber: storedLead.phoneNumber,
          firstName: storedLead.firstName,
          email: storedLead.email,
          chatId: storedLead.chatId,
          subscriberId: storedLead.subscriberId,
          userMessage: storedLead.userMessage,
          stored: true
        },
        timestamp: storedLead.timestamp
      });

    } else {
      console.log('❌ No phone number provided');
      return res.status(400).json({
        success: false,
        message: 'No phone number provided in lead data',
        data: leadData
      });
    }

  } catch (error) {
    console.error('BSP lead processing error:', error);
    return res.status(500).json({ 
      error: 'Internal server error',
      message: error.message 
    });
  }
}

// --- Enhanced WhatsApp Phone Number Detection ---
function getUserPhoneFromPayload(decryptedBody) {
  console.log('=== PHONE NUMBER DETECTION ===');
  
  // Method 1: Extract from WhatsApp Flow payload
  const flowCandidates = [
    decryptedBody?.user?.wa_id,
    decryptedBody?.user?.phone,
    decryptedBody?.phone_number,
    decryptedBody?.mobile_number,
    decryptedBody?.data?.phone_number,
    decryptedBody?.data?.user_phone,
    decryptedBody?.data?.mobile_number
  ];

  const flowPhone = flowCandidates.find((v) => typeof v === 'string' && v.trim().length > 0);
  
  if (flowPhone) {
    const digits = flowPhone.replace(/\D/g, '');
    if (digits) {
      const normalizedPhone = digits.length === 10 ? `91${digits}` : digits;
      console.log('📱 Phone from WhatsApp Flow:', normalizedPhone);
      return normalizedPhone;
    }
  }

  // Method 2: Get from latest BSP lead
  const latestLead = getBspLead('latest');
  if (latestLead?.phoneNumber) {
    const digits = latestLead.phoneNumber.replace(/\D/g, '');
    if (digits) {
      const normalizedPhone = digits.length === 10 ? `91${digits}` : digits;
      console.log('📱 Phone from latest BSP lead:', normalizedPhone, `(${latestLead.firstName || 'Unknown'})`);
      return normalizedPhone;
    }
  }

  console.log('❌ No phone number found in payload or BSP leads');
  return null;
}

// --- Enhanced Image Generation with BSP Integration ---
async function generateImageAndSendToUser(decryptedBody, actualImageData, productCategory, sceneDescription, priceOverlay) {
  console.log('🚀 Starting image generation and user notification...');
  
  try {
    // Generate the image
    const imageUrl = await generateImageFromAi(
      actualImageData,
      productCategory.trim(),
      sceneDescription && sceneDescription.trim() ? sceneDescription.trim() : null,
      priceOverlay && priceOverlay.trim() ? priceOverlay.trim() : null
    );
    
    console.log('✅ Image generation successful:', imageUrl);

    // Get user's phone number (from Flow payload or BSP lead)
    const toPhone = getUserPhoneFromPayload(decryptedBody);
    
    if (!toPhone) {
      console.warn('⚠️ Phone number not found; cannot send WhatsApp message');
      console.log('Available BSP leads:', {
        latest: bspLeadStore.latest?.phoneNumber || 'none',
        totalStored: bspLeadStore.byPhone.size,
        recent: bspLeadStore.recent.slice(0, 3).map(lead => ({ 
          phone: lead.phoneNumber, 
          name: lead.firstName 
        }))
      });
    } else {
      // Get lead info for personalized message
      const leadInfo = getBspLead(toPhone) || getBspLead('latest');
      
      const caption = createImageCaption(productCategory, priceOverlay, leadInfo);
      
      console.log('📤 Sending WhatsApp image to:', toPhone);
      console.log('📝 Caption:', caption);
      
      try {
        const waResp = await sendWhatsAppImageMessage(toPhone, imageUrl, caption);
        console.log('✅ WhatsApp image sent successfully:', JSON.stringify(waResp));
      } catch (sendErr) {
        console.error('❌ Failed to send WhatsApp image:', sendErr);
      }
    }

    return imageUrl;
  } catch (error) {
    console.error('❌ Image generation or sending failed:', error);
    throw error;
  }
}

// Create personalized image caption
function createImageCaption(productCategory, priceOverlay, leadInfo) {
  let caption = '';
  
  // Personalized greeting if we have lead info
  if (leadInfo?.firstName) {
    caption += `Hi ${leadInfo.firstName}! `;
  }
  
  // Product info
  caption += `Here's your enhanced ${productCategory}`;
  
  // Price if provided
  if (priceOverlay && priceOverlay.trim()) {
    caption += ` — ${priceOverlay.trim()}`;
  }
  
  caption += ' image! 🎨✨';
  
  return caption;
}

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

  if (action === 'data_exchange') {
    console.log('=== DATA EXCHANGE ACTION ===');

    if (data && typeof data === 'object') {
      const { scene_description, price_overlay, product_image, product_category } = data;

      console.log('=== FIELD VALIDATION ===');
      console.log('product_image:', product_image ? 'present' : 'MISSING (REQUIRED)');
      console.log('product_category:', product_category ? `"${product_category}"` : 'MISSING (REQUIRED)');
      console.log('scene_description:', scene_description ? `"${scene_description}"` : 'not provided (optional)');
      console.log('price_overlay
