// supabase/functions/verify-razorpay-payment/index.ts
import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import crypto from 'https://deno.land/std@0.177.0/node/crypto.ts'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
}

serve(async (req) => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response('ok', { 
      headers: corsHeaders,
      status: 200 
    })
  }

  try {
    // Only allow POST
    if (req.method !== 'POST') {
      return new Response(
        JSON.stringify({ error: 'Method not allowed' }),
        { 
          status: 405,
          headers: { 
            'Content-Type': 'application/json',
            ...corsHeaders 
          }
        }
      )
    }

    // Get authorization header
    const authHeader = req.headers.get('Authorization')
    if (!authHeader) {
      return new Response(
        JSON.stringify({ 
          success: false,
          error: 'Missing authorization header',
          code: 401 
        }),
        { 
          status: 401,
          headers: { 
            'Content-Type': 'application/json',
            ...corsHeaders 
          }
        }
      )
    }

    // Verify the token (optional - you can also use service role for verification)
    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_ANON_KEY') ?? ''
    )

    const token = authHeader.replace('Bearer ', '')
    const { data: { user }, error: authError } = await supabaseClient.auth.getUser(token)

    if (authError || !user) {
      return new Response(
        JSON.stringify({ 
          success: false,
          error: 'Invalid authentication',
          code: 401 
        }),
        { 
          status: 401,
          headers: { 
            'Content-Type': 'application/json',
            ...corsHeaders 
          }
        }
      )
    }

    // Parse request body
    const { 
      razorpay_payment_id, 
      razorpay_order_id, 
      razorpay_signature,
      orderReference,
      idempotencyKey 
    } = await req.json()

    // Initialize admin client for database operations
    const supabaseAdmin = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
    )

    // Verify signature
    const body = razorpay_order_id + '|' + razorpay_payment_id
    const expectedSignature = crypto
      .createHmac('sha256', Deno.env.get('RAZORPAY_KEY_SECRET')!)
      .update(body.toString())
      .digest('hex')

    if (expectedSignature !== razorpay_signature) {
      throw new Error('Invalid signature')
    }

    // Get pending order
    const { data: pendingOrder, error: fetchError } = await supabaseAdmin
      .from('pending_orders')
      .select('*')
      .eq('order_reference', orderReference)
      .eq('razorpay_order_id', razorpay_order_id)
      .single()

    if (fetchError || !pendingOrder) {
      throw new Error('Pending order not found')
    }

    // Create actual order
    const { data: order, error: orderError } = await supabaseAdmin
      .from('orders')
      .insert({
        user_id: pendingOrder.user_id,
        address_id: pendingOrder.address_id,
        total_amount: pendingOrder.total_amount,
        shipping_cost: pendingOrder.shipping_cost,
        payment_method: 'razorpay',
        payment_status: 'paid',
        order_status: 'confirmed',
        razorpay_payment_id,
        razorpay_order_id,
        razorpay_signature,
        order_reference: orderReference
      })
      .select()
      .single()

    if (orderError) throw orderError

    // Add order items
    const orderItems = pendingOrder.cart_items.map((item: any) => ({
      order_id: order.id,
      variant_id: item.variant_id,
      quantity: item.quantity,
      price: item.price
    }))

    const { error: itemsError } = await supabaseAdmin
      .from('order_items')
      .insert(orderItems)

    if (itemsError) throw itemsError

    // Delete pending order
    await supabaseAdmin
      .from('pending_orders')
      .delete()
      .eq('order_reference', orderReference)

    // At the end of your verify function, return:
    return new Response(
      JSON.stringify({ 
        success: true,
        message: 'Payment verified successfully'
      }),
      { 
        headers: { 
          'Content-Type': 'application/json',
          ...corsHeaders 
        },
        status: 200 
      }
    );
    
  } catch (error) {
    console.error('Verification error:', error.message)
    
    return new Response(
      JSON.stringify({ 
        success: false, 
        error: error.message 
      }),
      { 
        headers: { 
          'Content-Type': 'application/json',
          ...corsHeaders 
        },
        status: 400 
      }
    )
  }
})