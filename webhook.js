// Vercel Node.js API Route for WhatsApp Flow with Gemini API
// Place this file at: pages/api/webhook.js or app/api/webhook/route.js

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

    // Convert ArrayBuffer to base64 string
    const encryptedUint8Array = new Uint8Array(encryptedBuffer);
    return Buffer.from(encryptedUint8Array).toString('base64');
  } catch (error) {
    console.error('Encryption failed:', error);
    throw new Error(`Encryption failed: ${error.message}`);
  }
}

// Gemini API call for Vercel Node.js
async function generateImageFromAi(productImageBase64, sceneDescription, priceOverlay) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error("Missing GEMINI_API_KEY environment variable");
  }

  // Clean the base64 data - remove data URL prefix if present
  let cleanBase64 = productImageBase64;
  if (productImageBase64.startsWith('data:')) {
    const base64Index = productImageBase64.indexOf(',');
    if (base64Index !== -1) {
      cleanBase64 = productImageBase64.substring(base64Index + 1);
    }
  }

  // Use the correct Gemini REST API endpoint for image generation
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-image-preview:generateContent?key=${apiKey}`;

  // Build request body using the correct structure for REST API
  const requestBody = {
    contents: [
      {
        parts: [
          {
            text: `Create a picture of this product in the following scene: "${sceneDescription}". Overlay the price "${priceOverlay}" stylishly onto the image.`
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
      temperature: 0.7,
      maxOutputTokens: 1024
    }
  };

  console.log("Sending request to Gemini REST API...");
  console.log("Request structure:", JSON.stringify({
    contents: [
      {
        parts: [
          {
            text: requestBody.contents[0].parts[0].text
          },
          {
            inlineData: {
              mimeType: requestBody.contents[0].parts[1].inlineData.mimeType,
              data: "[BASE64_TRUNCATED]"
            }
          }
        ]
      }
    ],
    generationConfig: requestBody.generationConfig
  }, null, 2));

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(requestBody)
    });

    console.log("Response status:", response.status);
    console.log("Response headers:", Object.fromEntries(response.headers.entries()));

    if (!response.ok) {
      const errorText = await response.text();
      console.error("Gemini API error response:", errorText);
      try {
        const errorJson = JSON.parse(errorText);
        throw new Error(`Gemini API failed (${response.status}): ${JSON.stringify(errorJson, null, 2)}`);
      } catch (parseError) {
        throw new Error(`Gemini API failed (${response.status}): ${errorText}`);
      }
    }

    const responseData = await response.json();
    console.log("Gemini API response:", JSON.stringify(responseData, null, 2));

    const candidate = responseData?.candidates?.[0];
    if (!candidate?.content?.parts) {
      throw new Error("No response parts found in Gemini API response");
    }

    // Look for image data in response parts
    for (const part of candidate.content.parts) {
      if (part.inlineData) {
        const generatedMimeType = part.inlineData.mimeType;
        const generatedBase64 = part.inlineData.data;
        console.log("Image generated successfully");
        return `data:${generatedMimeType};base64,${generatedBase64}`;
      }
    }

    // If no image found, check for text response (which might indicate an error)
    const textPart = candidate.content.parts.find((p) => p.text);
    if (textPart) {
      throw new Error(`Model returned text instead of image: ${textPart.text}`);
    }

    throw new Error("No image data found in Gemini API response");
  } catch (error) {
    console.error('Error in generateImageFromAi:', error);
    if (error.message.includes('fetch')) {
      throw new Error(`Network error calling Gemini API: ${error.message}`);
    }
    throw error;
  }
}

// Alternative simpler version for debugging
async function generateImageFromAiSimple(productImageBase64, sceneDescription, priceOverlay) {
  console.log("Using simplified version...");
  
  // First, upload the user's image to reference-photos bucket
  const referenceImageUrl = await uploadReferenceImageToSupabase(productImageBase64);
  
  const apiKey = process.env.GEMINI_API_KEY;
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-image-preview:generateContent?key=${apiKey}`;

  // Get base64 from the public URL
  const base64FromUrl = await getImageAsBase64FromUrl(referenceImageUrl);

  const body = {
    contents: [
      {
        parts: [
          {
            text: `Create a stylized product image in this scene: ${sceneDescription}. Add price overlay: ${priceOverlay}`
          },
          {
            inlineData: {
              mimeType: "image/jpeg",
              data: base64FromUrl
            }
          }
        ]
      }
    ]
  };

  console.log("Making simplified Gemini API call...");
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });

  if (!response.ok) {
    const error = await response.text();
    console.error("API Error:", error);
    throw new Error(`Gemini API error: ${error}`);
  }

  const data = await response.json();
  const imagePart = data.candidates?.[0]?.content?.parts?.find((p) => p.inlineData);

  if (!imagePart) {
    throw new Error("No image generated");
  }

  const generatedMimeType = imagePart.inlineData.mimeType;
  const generatedBase64 = imagePart.inlineData.data;
  
  // Upload generated image to generated-images bucket
  const publicUrl = await uploadGeneratedImageToSupabase(generatedBase64, generatedMimeType);
  return publicUrl;
}

// --- Request Handlers ---
async function handleDataExchange(decryptedBody) {
  const { action, screen, data } = decryptedBody;
  console.log(`Processing action: ${action} for screen: ${screen}`);
  console.log('Full decrypted body:', JSON.stringify(decryptedBody, null, 2));
  console.log('Data received:', JSON.stringify(data, null, 2));

  if (action === 'INIT') {
    return {
      screen: 'COLLECT_INFO',
      data: {}
    };
  }

  // Handle data_exchange for any screen that has the required data
  if (action === 'data_exchange') {
    console.log('Data exchange action detected');
    console.log('Available data keys:', data ? Object.keys(data) : 'No data');

    // Check if we have the required fields for image generation
    if (data && typeof data === 'object') {
      const { scene_description, price_overlay, product_image, product_category } = data;

      console.log('scene_description:', scene_description ? 'present' : 'missing');
      console.log('price_overlay:', price_overlay ? 'present' : 'missing');
      console.log('product_image:', product_image ? 'present' : 'missing');
      console.log('product_category:', product_category ? product_category : 'not specified');

      if (scene_description && price_overlay && product_image) {
        console.log('All required data present, generating enhanced image...');
        console.log(`Using category-specific prompting for: ${product_category || 'general'}`);
        try {
          const imageUrl = await generateImageFromAi(
            product_image, 
            scene_description, 
            price_overlay, 
            product_category || 'general'
          );
          return {
            screen: 'SUCCESS_SCREEN',
            data: {
              image_url: imageUrl
            }
          };
        } catch (e) {
          console.error('Image generation failed', e);
          return {
            screen: 'COLLECT_INFO',
            data: {
              error_message: `Image generation failed: ${e.message}`
            }
          };
        }
      } else {
        // Missing some required data
        const missingFields = [];
        if (!scene_description) missingFields.push('scene_description');
        if (!price_overlay) missingFields.push('price_overlay');
        if (!product_image) missingFields.push('product_image');

        console.log('Missing required fields:', missingFields.join(', '));
        return {
          screen: 'COLLECT_INFO',
          data: {
            error_message: `Missing required fields: ${missingFields.join(', ')}. Please fill in all required information.`
          }
        };
      }
    } else {
      console.log('No data object found in request');
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
    // Handle other back navigation
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

      // WhatsApp expects just the encrypted string as the response body
      res.setHeader('Content-Type', 'application/json');
      return res.status(200).send(encryptedResponse);
    } catch (error) {
      console.error('Error processing request:', error);
      return res.status(500).json({ error: `Internal Server Error: ${error.message}` });
    }
  }

  return res.status(405).json({ error: 'Method Not Allowed' });
}
