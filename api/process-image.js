// api/process-image.js (CommonJS version)
const { createHash, createHmac, createDecipheriv, createCipheriv, randomBytes } = require('crypto');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');

// WhatsApp API config
const WHATSAPP_TOKEN = process.env.WHATSAPP_TOKEN;
const WHATSAPP_PHONE_NUMBER_ID = process.env.WHATSAPP_PHONE_NUMBER_ID;
const WHATSAPP_API_VERSION = process.env.WHATSAPP_API_VERSION || 'v23.0';

// BSP Lead Storage (should be shared with main webhook)
const bspLeadStore = {
  latest: null,
  byPhone: new Map(),
  bySession: new Map(),
  recent: []
};

function getBspLead(identifier = 'latest') {
  if (identifier === 'latest') {
    return bspLeadStore.latest;
  }
  
  if (bspLeadStore.byPhone.has(identifier)) {
    return bspLeadStore.byPhone.get(identifier);
  }
  
  if (bspLeadStore.bySession.has(identifier)) {
    const phone = bspLeadStore.bySession.get(identifier);
    return bspLeadStore.byPhone.get(phone);
  }
  
  return null;
}

function getUserPhoneFromPayload(decryptedBody) {
  console.log('=== PHONE NUMBER DETECTION ===');
  
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

function createImageCaption(productCategory, priceOverlay, leadInfo) {
  let caption = '';
  
  if (leadInfo?.firstName) {
    caption += `Hi ${leadInfo.firstName}! `;
  }
  
  caption += `Here's your enhanced ${productCategory}`;
  
  if (priceOverlay && priceOverlay.trim()) {
    caption += ` — ${priceOverlay.trim()}`;
  }
  
  caption += ' image! 🎨✨';
  
  return caption;
}

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

async function generateImageAndSendToUser(decryptedBody, actualImageData, productCategory, sceneDescription, priceOverlay) {
  console.log('🚀 Starting image generation and user notification...');
  
  try {
    const imageUrl = await generateImageFromAi(
      actualImageData,
      productCategory.trim(),
      sceneDescription && sceneDescription.trim() ? sceneDescription.trim() : null,
      priceOverlay && priceOverlay.trim() ? priceOverlay.trim() : null
    );
    
    console.log('✅ Image generation successful:', imageUrl);

    const toPhone = getUserPhoneFromPayload(decryptedBody);
    
    if (!toPhone) {
      console.warn('⚠️ Phone number not found; cannot send WhatsApp message');
    } else {
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

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { decryptedBody, actualImageData, productCategory, sceneDescription, priceOverlay } = req.body;
    
    console.log('🚀 Processing image in dedicated endpoint...');
    console.log('Product Category:', productCategory);
    console.log('Scene Description:', sceneDescription);
    console.log('Price Overlay:', priceOverlay);
    
    const imageUrl = await generateImageAndSendToUser(
      decryptedBody,
      actualImageData,
      productCategory,
      sceneDescription,
      priceOverlay
    );
    
    console.log('✅ Image processing completed:', imageUrl);
    
    return res.status(200).json({ success: true, imageUrl });
  } catch (error) {
    console.error('❌ Image processing failed:', error);
    return res.status(500).json({ success: false, error: error.message });
  }
};
