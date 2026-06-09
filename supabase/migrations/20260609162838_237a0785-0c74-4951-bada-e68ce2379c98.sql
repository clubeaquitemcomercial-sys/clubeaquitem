
-- Subscribers: remove dangerous public SELECT policy (cpf = cpf was always true)
DROP POLICY IF EXISTS "Subscribers can view own data by CPF" ON public.subscribers;

-- Subscribers: remove overly permissive UPDATE policies
DROP POLICY IF EXISTS "Allow password update on first access" ON public.subscribers;
DROP POLICY IF EXISTS "Service role can update subscribers" ON public.subscribers;

-- Allow only admins to UPDATE subscribers via Data API.
-- The member-auth edge function uses the service_role key, which bypasses RLS.
CREATE POLICY "Admins can update subscribers"
ON public.subscribers
FOR UPDATE
TO authenticated
USING (public.has_role(auth.uid(), 'admin'))
WITH CHECK (public.has_role(auth.uid(), 'admin'));

-- Partners: remove public INSERT policy and restrict to admins
DROP POLICY IF EXISTS "Anyone can insert partners" ON public.partners;

CREATE POLICY "Admins can insert partners"
ON public.partners
FOR INSERT
TO authenticated
WITH CHECK (public.has_role(auth.uid(), 'admin'));
