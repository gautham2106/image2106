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
      console.log('price_overlay:', price_overlay ? `"${price_overlay}"` : 'not provided (optional)');

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

      console.log('🚀 Proceeding to send job to processing function...');
      
      try {
        // Get user's phone number for context
        const userPhone = getUserPhoneFromPayload(decryptedBody);
        
        // Forward to process-job function
        const processingPayload = {
          actualImageData,
          productCategory: product_category.trim(),
          sceneDescription: scene_description && scene_description.trim() ? scene_description.trim() : null,
          priceOverlay: price_overlay && price_overlay.trim() ? price_overlay.trim() : null,
          userPhone,
          decryptedBody
        };

        console.log('📤 Sending to process-job function...');
        
        // Non-blocking call to processing function
        const vercelUrl = 'https://image2106.vercel.app';
        fetch(`${vercelUrl}/api/process-job`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(processingPayload)
        }).catch(error => {
          console.error('❌ Failed to send to process-job:', error);
        });

        // Immediately return success to WhatsApp Flow
        return { 
          screen: 'SUCCESS_SCREEN', 
          data: { 
            message: 'Your image is being processed and will be sent to you shortly!' 
          } 
        };
      } catch (e) {
        console.error('❌ Failed to forward to processing function:', e);
        return {
          screen: 'COLLECT_IMAGE_SCENE',
          data: { error_message: `Processing failed: ${e.message}. Please try again.` }
        };
      }
    } else {
      return { screen: 'COLLECT_INFO', data: { error_message: 'No data received. Please fill in the form.' } };
    }
  }

  if (action === 'BACK') {
    if (screen === 'COLLECT_IMAGE_SCENE') {
      return { screen: 'COLLECT_INFO', data: {} };
    }
    return { screen: 'COLLECT_INFO', data: {} };
  }

  console.log(`Unhandled action/screen combination: ${action}/${screen}`);
  return { screen: 'COLLECT_INFO', data: { error_message: 'An unexpected error occurred.' } };
}

async function handleHealthCheck() {
  return { data: { status: 'active' } };
}

async function handleErrorNotification(decryptedBody) {
  console.log('Error notification received:', decryptedBody);
  return { data: { acknowledged: true } };
}

// --- Debug endpoint to check BSP lead storage ---
async function handleDebugLeads(req, res) {
  console.log('=== DEBUG LEADS ENDPOINT ===');
  
  const debugInfo = {
    latest: bspLeadStore.latest,
    totalStored: bspLeadStore.byPhone.size,
    recentCount: bspLeadStore.recent.length,
    phoneNumbers: Array.from(bspLeadStore.byPhone.keys()),
    recentLeads: bspLeadStore.recent.slice(0, 5).map(lead => ({
      phone: lead.phoneNumber,
      name: lead.firstName,
      timestamp: lead.timestamp,
      id: lead.id
    })),
    sessionMappings: Array.from(bspLeadStore.bySession.entries())
  };
  
  console.log('Debug info:', JSON.stringify(debugInfo, null, 2));
  
  return res.status(200).json({
    success: true,
    message: 'BSP Lead Storage Debug Info',
    data: debugInfo,
    timestamp: new Date().toISOString()
  });
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

  // DEBUG ENDPOINT: Check BSP lead storage
  if (req.method === 'GET' && req.url?.includes('/debug-leads')) {
    return handleDebugLeads(req, res);
  }

  // FIRST: Check if this is a BSP lead webhook (before any WhatsApp Flow processing)
  if (req.method === 'POST' && req.body) {
    // BSP structure check: has phoneNumber/firstName/email/chat_id/first_name but no WhatsApp Flow encryption
    const isBspLead = req.body.phoneNumber !== undefined || 
                     req.body.firstName !== undefined || 
                     req.body.email !== undefined ||
                     req.body.chat_id !== undefined ||
                     req.body.first_name !== undefined;
    
    const isWhatsAppFlow = req.body.encrypted_aes_key !== undefined || 
                          req.body.encrypted_flow_data !== undefined || 
                          req.body.initial_vector !== undefined;
    
    if (isBspLead && !isWhatsAppFlow) {
      console.log('🔄 Processing BSP lead webhook');
      return handleBspLead(req, res);
    }
  }

  // Continue with existing WhatsApp Flow logic
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
