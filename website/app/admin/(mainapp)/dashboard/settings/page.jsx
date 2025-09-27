"use client";
import React, { useEffect, useMemo, useState } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";
import { razorpayAdminService } from "@/services/admin/razorpay.service";

function Masked({ value, visible = false }) {
  const masked = useMemo(() => (value ? "•".repeat(Math.max(6, Math.min(12, value.length))) : ""), [value]);
  return <span className="font-mono text-sm">{visible ? value : masked}</span>;
}

const Settings = () => {
  // Razorpay state
  const [rzpLoading, setRzpLoading] = useState(false);
  const [rzpSaving, setRzpSaving] = useState(false);
  const [rzp, setRzp] = useState({ keyId: "", keySecret: "", webhookSecret: "" });
  const [activeRzp, setActiveRzp] = useState(null);
  const [showSecrets, setShowSecrets] = useState(false);

  // Feature toggles (local only for now)
  const [features, setFeatures] = useState({
    maintenanceMode: false,
    allowRegistrations: true,
    enableCoupons: true,
  });

  useEffect(() => {
    const loadActive = async () => {
      setRzpLoading(true);
      try {
        const res = await razorpayAdminService.getActiveCredential();
        if (res?.success && res?.credential) {
          setActiveRzp(res.credential);
          setRzp((prev) => ({
            ...prev,
            keyId: res.credential.keyId || "",
            webhookSecret: res.credential.webhookSecret || "",
          }));
        }
      } catch (e) {
        // It's fine if none configured yet
      } finally {
        setRzpLoading(false);
      }
    };
    loadActive();
  }, []);

  const onSaveRazorpay = async (e) => {
    e.preventDefault();
    if (!rzp.keyId || !rzp.keySecret) {
      toast.error("Please enter both Key ID and Key Secret");
      return;
    }
    setRzpSaving(true);
    try {
      const payload = {
        keyId: rzp.keyId.trim(),
        keySecret: rzp.keySecret.trim(),
        webhookSecret: rzp.webhookSecret?.trim() || undefined,
      };
      const res = await razorpayAdminService.addCredential(payload);
      if (res?.success) {
        setActiveRzp(res.credential);
        setRzp((prev) => ({ ...prev, keySecret: "" }));
        toast.success("Razorpay credentials saved and activated");
      } else {
        toast.error(res?.error || "Failed to save credentials");
      }
    } catch (err) {
      toast.error("Failed to save credentials");
    } finally {
      setRzpSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="text-sm text-muted-foreground">Manage your platform configuration.</p>
      </div>

      <Tabs defaultValue="payments" className="w-full">
        <TabsList>
          <TabsTrigger value="payments">Payments</TabsTrigger>
          {/* <TabsTrigger value="email">Email</TabsTrigger>
          <TabsTrigger value="site">Site</TabsTrigger>
          <TabsTrigger value="features">Features</TabsTrigger> */}
        </TabsList>

        <TabsContent value="payments" className="mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Razorpay Credentials</CardTitle>
                <CardDescription>
                  Configure your Razorpay keys. Saving new credentials will automatically activate them.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={onSaveRazorpay} className="space-y-4">
                  {activeRzp ? (
                    <div className="rounded-md border p-3 text-sm">
                      <div className="flex items-center justify-between gap-4">
                        <div>
                          <p className="font-medium">Active Credential</p>
                          <p className="text-muted-foreground">
                            Key ID: <Masked value={activeRzp.keyId} visible={showSecrets} />
                          </p>
                          {activeRzp.updatedAt && (
                            <p className="text-muted-foreground">Updated: {new Date(activeRzp.updatedAt).toLocaleString()}</p>
                          )}
                        </div>
                        <div className="flex items-center gap-2">
                          <Switch
                            id="show-secrets"
                            checked={showSecrets}
                            onCheckedChange={setShowSecrets}
                          />
                          <Label htmlFor="show-secrets">Show</Label>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="rounded-md border p-3 text-sm text-muted-foreground">
                      {rzpLoading ? "Loading current credential..." : "No active Razorpay credential configured yet."}
                    </div>
                  )}

                  <div className="grid gap-3">
                    <Label htmlFor="keyId">Key ID</Label>
                    <Input
                      id="keyId"
                      placeholder="rzp_test_********"
                      value={rzp.keyId}
                      onChange={(e) => setRzp((p) => ({ ...p, keyId: e.target.value }))}
                    />
                  </div>

                  <div className="grid gap-3">
                    <Label htmlFor="keySecret">Key Secret</Label>
                    <Input
                      id="keySecret"
                      type="password"
                      placeholder="Enter key secret"
                      value={rzp.keySecret}
                      onChange={(e) => setRzp((p) => ({ ...p, keySecret: e.target.value }))}
                    />
                  </div>

                

                  <div className="flex items-center gap-3 pt-2">
                    <Button type="submit" disabled={rzpSaving}>
                      {rzpSaving ? "Saving..." : "Save & Activate"}
                    </Button>
                    {activeRzp && (
                      <p className="text-xs text-muted-foreground">Saving creates a new credential and deactivates old ones.</p>
                    )}
                  </div>
                </form>
              </CardContent>
            </Card>

        
          </div>
        </TabsContent>

        <TabsContent value="email" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>SMTP Settings</CardTitle>
              <CardDescription>Configure email delivery (placeholder UI).</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-4 sm:grid-cols-2">
              <div className="grid gap-2">
                <Label htmlFor="smtpHost">SMTP Host</Label>
                <Input id="smtpHost" placeholder="smtp.example.com" />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="smtpPort">SMTP Port</Label>
                <Input id="smtpPort" placeholder="587" />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="smtpUser">Username</Label>
                <Input id="smtpUser" placeholder="no-reply@example.com" />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="smtpPass">Password</Label>
                <Input id="smtpPass" type="password" placeholder="••••••••" />
              </div>
              <div className="sm:col-span-2 flex items-center justify-between rounded-md border p-3">
                <div>
                  <p className="font-medium">Use TLS</p>
                  <p className="text-sm text-muted-foreground">Enable STARTTLS if your provider requires it.</p>
                </div>
                <Switch defaultChecked />
              </div>
              <div className="sm:col-span-2">
                <Button type="button" onClick={() => toast.message("SMTP settings save coming soon")}>Save</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="site" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>Site Information</CardTitle>
              <CardDescription>Branding and general site metadata (placeholder UI).</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-4 sm:grid-cols-2">
              <div className="grid gap-2">
                <Label htmlFor="siteName">Site Name</Label>
                <Input id="siteName" placeholder="LMS" />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="siteEmail">Support Email</Label>
                <Input id="siteEmail" placeholder="support@example.com" />
              </div>
              <div className="grid gap-2 sm:col-span-2">
                <Label htmlFor="siteUrl">Site URL</Label>
                <Input id="siteUrl" placeholder="https://example.com" />
              </div>
              <div className="sm:col-span-2">
                <Button type="button" onClick={() => toast.message("Site info save coming soon")}>Save</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="features" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>Feature Toggles</CardTitle>
              <CardDescription>Enable or disable features across the app.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between rounded-md border p-3">
                <div>
                  <p className="font-medium">Maintenance Mode</p>
                  <p className="text-sm text-muted-foreground">Temporarily show maintenance page to users.</p>
                </div>
                <Switch
                  checked={features.maintenanceMode}
                  onCheckedChange={(v) => setFeatures((f) => ({ ...f, maintenanceMode: v }))}
                />
              </div>

              <div className="flex items-center justify-between rounded-md border p-3">
                <div>
                  <p className="font-medium">Allow New Registrations</p>
                  <p className="text-sm text-muted-foreground">Control if users can sign up.</p>
                </div>
                <Switch
                  checked={features.allowRegistrations}
                  onCheckedChange={(v) => setFeatures((f) => ({ ...f, allowRegistrations: v }))}
                />
              </div>

              <div className="flex items-center justify-between rounded-md border p-3">
                <div>
                  <p className="font-medium">Enable Coupons</p>
                  <p className="text-sm text-muted-foreground">Toggle coupon usage at checkout.</p>
                </div>
                <Switch
                  checked={features.enableCoupons}
                  onCheckedChange={(v) => setFeatures((f) => ({ ...f, enableCoupons: v }))}
                />
              </div>

              <div>
                <Button type="button" onClick={() => toast.message("Feature toggles save coming soon")}>Save</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default Settings;
