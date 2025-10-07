"use client";
import React, { useEffect, useMemo, useState } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import axiosInstance from "@/app/utils/axiosinterceptor";

import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";
import { razorpayAdminService } from "@/services/admin/razorpay.service";
import { settingsAdminService } from "@/services/admin/settings.service";
import { getMediaUrl } from "@/app/utils/getAssetsUrl";

function Masked({ value, visible = false }) {
  const masked = useMemo(
    () => (value ? "•".repeat(Math.max(6, Math.min(12, value.length))) : ""),
    [value]
  );
  return <span className="font-mono text-sm">{visible ? value : masked}</span>;
}

// Supported Currencies
const supportedCurrencies = {
  USD: { symbol: "$", position: "prefix" },
  EUR: { symbol: "€", position: "prefix" },
  INR: { symbol: "₹", position: "prefix" },
};

const Settings = () => {
  // Razorpay state
  const [rzpLoading, setRzpLoading] = useState(false);
  const [rzpSaving, setRzpSaving] = useState(false);
  const [rzp, setRzp] = useState({
    keyId: "",
    keySecret: "",
    webhookSecret: "",
  });

  const [logoFile, setLogoFile] = useState(null);
  const [logoPreview, setLogoPreview] = useState("");

  const [basicInfo, setBasicInfo] = useState({
    platformName: "",
    platformUrl: "",
    contactEmail: "",
    supportPhone: "",
    address: "",
    branding: {
      logoUrl: "",
      faviconUrl: "",
    },
  });

  const [activeRzp, setActiveRzp] = useState(null);
  const [showSecrets, setShowSecrets] = useState(false);

  // Feature toggles
  const [features, setFeatures] = useState({
    maintenanceMode: false,
    allowRegistrations: true,
    enableCoupons: true,
  });

  // Platform settings state
  const [settingsLoading, setSettingsLoading] = useState(false);
  const [settingsSaving, setSettingsSaving] = useState(false);
  const [settings, setSettings] = useState({
    currency: { code: "USD", symbol: "$", position: "prefix" },
    commissionPercent: 15,
    taxPercent: 0,
    payoutThreshold: 50,
    defaultLanguage: "en",
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
      } catch {
        // no active creds
      } finally {
        setRzpLoading(false);
      }
    };
    const loadSettings = async () => {
      setSettingsLoading(true);
      try {
        const resp = await settingsAdminService.get();
        if (resp?.settings) {
          const s = resp.settings;
          setSettings({
            currency: {
              code: s.currency?.code || "USD",
              symbol: s.currency?.symbol || "$",
              position: s.currency?.position || "prefix",
            },
            commissionPercent: s.commissionPercent ?? 15,
            taxPercent: s.taxPercent ?? 0,
            payoutThreshold: s.payoutThreshold ?? 50,
            defaultLanguage: s.defaultLanguage || "en",
          });
          setBasicInfo({
            platformName: s.platformName || "",
            platformUrl: s.platformUrl || "",
            contactEmail: s.contactEmail || "",
            supportPhone: s.supportPhone || "",
            address: s.address || "",
            branding: {
              logoUrl: s.branding?.logoUrl || "",
              faviconUrl: s.branding?.faviconUrl || "",
            },
          });
          if (s.branding?.logoUrl) {
            setLogoPreview(s.branding.logoUrl);
          }
        }
      } finally {
        setSettingsLoading(false);
      }
    };
    loadActive();
    loadSettings();
  }, []);
  const handleLogoChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      setLogoFile(file);

      // Create preview
      const reader = new FileReader();
      reader.onloadend = () => {
        setLogoPreview(reader.result);
      };
      reader.readAsDataURL(file);
    }
  };

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
    } catch {
      toast.error("Failed to save credentials");
    } finally {
      setRzpSaving(false);
    }
  };
  const [basicSaving, setBasicSaving] = useState(false);

  const onSaveBasicInfo = async (e) => {
    e.preventDefault();
    setBasicSaving(true);
    try {
      const formData = new FormData();

      // Append all fields individually
      formData.append("platformName", basicInfo.platformName);
      formData.append("platformUrl", basicInfo.platformUrl);
      formData.append("contactEmail", basicInfo.contactEmail);
      formData.append("supportPhone", basicInfo.supportPhone);
      formData.append("address", basicInfo.address);
      formData.append("branding[logoUrl]", basicInfo.branding.logoUrl);
      formData.append("branding[faviconUrl]", basicInfo.branding.faviconUrl);

      if (logoFile) {
        formData.append("logo", logoFile);
      }

      // Use axios directly
      const res = await axiosInstance.put("/settings", formData, {
        headers: {
          "Content-Type": "multipart/form-data",
        },
      });

      if (res.data?.settings) {
        // Update local state
        const updatedSettings = res.data.settings;
        setBasicInfo({
          platformName: updatedSettings.platformName,
          platformUrl: updatedSettings.platformUrl,
          contactEmail: updatedSettings.contactEmail,
          supportPhone: updatedSettings.supportPhone,
          address: updatedSettings.address,
          branding: {
            logoUrl: updatedSettings.branding?.logoUrl || "",
            faviconUrl: updatedSettings.branding?.faviconUrl || "",
          },
        });

        if (updatedSettings.branding?.logoUrl) {
          setLogoPreview(updatedSettings.branding.logoUrl);
        }

        setLogoFile(null);
        toast.success("Basic Info updated!");
      } else {
        toast.error("Failed to update basic info");
      }
    } catch (error) {
      console.error("Error saving basic info:", error);
      toast.error("Error saving basic info");
    } finally {
      setBasicSaving(false);
    }
  };
  const clearLogo = () => {
    setLogoFile(null);
    setLogoPreview(basicInfo.branding.logoUrl); // Revert to existing logo
  };
  const onSaveSettings = async (e) => {
    e.preventDefault();
    setSettingsSaving(true);
    try {
      // Create a new object with the settings, ensuring currency is a proper object
      const payload = {
        ...settings,
        // Ensure currency is an object with the expected properties
        currency: {
          code: settings.currency?.code || "USD",
          symbol: settings.currency?.symbol || "$",
          position: settings.currency?.position || "prefix",
        },
        commissionPercent: Number(settings.commissionPercent),
        taxPercent: Number(settings.taxPercent),
        payoutThreshold: Number(settings.payoutThreshold),
      };

      const res = await settingsAdminService.update(payload);
      if (res && (res.statusCode === 200 || res.message === 'Settings updated')) {
        toast.success("Settings saved successfully");
      } else {
        toast.error(res?.error || res?.message || "Failed to save settings");
      }
    } catch {
      toast.error("Failed to save settings");
    } finally {
      setSettingsSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="text-sm text-muted-foreground">
          Manage your platform configuration.
        </p>
      </div>

      <Tabs defaultValue="basicInfo" className="w-full">
        <TabsList>
          {" "}
          <TabsTrigger value="basicInfo">Basic Info</TabsTrigger>
          <TabsTrigger value="payments">Payments</TabsTrigger>
          {/* <TabsTrigger value="email">Email</TabsTrigger>
          <TabsTrigger value="site">Site</TabsTrigger>
          <TabsTrigger value="features">Features</TabsTrigger> */}
        </TabsList>

        {/* Payments Tab */}
        <TabsContent value="payments" className="mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Razorpay Card */}
            <Card>
              <CardHeader>
                <CardTitle>Razorpay Credentials</CardTitle>
                <CardDescription>Configure your Razorpay keys.</CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={onSaveRazorpay} className="space-y-4">
                  {/* Active Razorpay Info */}
                  {activeRzp ? (
                    <div className="rounded-md border p-3 text-sm">
                      <div className="flex items-center justify-between gap-4">
                        <div>
                          <p className="font-medium">Active Credential</p>
                          <p className="text-muted-foreground">
                            Key ID:{" "}
                            <Masked
                              value={activeRzp.keyId}
                              visible={showSecrets}
                            />
                          </p>
                          {activeRzp.updatedAt && (
                            <p className="text-muted-foreground">
                              Updated:{" "}
                              {new Date(activeRzp.updatedAt).toLocaleString()}
                            </p>
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
                      {rzpLoading
                        ? "Loading..."
                        : "No active Razorpay credential configured yet."}
                    </div>
                  )}

                  {/* Razorpay Inputs */}
                  <div className="grid gap-3">
                    <Label htmlFor="keyId">Key ID</Label>
                    <Input
                      id="keyId"
                      placeholder="rzp_test_********"
                      value={rzp.keyId}
                      onChange={(e) =>
                        setRzp((p) => ({ ...p, keyId: e.target.value }))
                      }
                    />
                  </div>

                  <div className="grid gap-3">
                    <Label htmlFor="keySecret">Key Secret</Label>
                    <Input
                      id="keySecret"
                      type="password"
                      placeholder="Enter key secret"
                      value={rzp.keySecret}
                      onChange={(e) =>
                        setRzp((p) => ({ ...p, keySecret: e.target.value }))
                      }
                    />
                  </div>

                  <div className="flex items-center gap-3 pt-2">
                    <Button type="submit" disabled={rzpSaving}>
                      {rzpSaving ? "Saving..." : "Save & Activate"}
                    </Button>
                    {activeRzp && (
                      <p className="text-xs text-muted-foreground">
                        Saving creates a new credential and deactivates old
                        ones.
                      </p>
                    )}
                  </div>
                </form>
              </CardContent>
            </Card>

            {/* Commerce Settings Card */}
            <Card>
              <CardHeader>
                <CardTitle>Commerce Settings</CardTitle>
                <CardDescription>Currency and platform fees.</CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={onSaveSettings} className="space-y-4">
                  <div className="grid gap-3 sm:grid-cols-3">
                    {/* Currency Code Dropdown */}
                    <div className="grid gap-2">
                      <Label htmlFor="currencyCode">Currency</Label>
                      <select
                        id="currencyCode"
                        className="h-10 rounded-md border px-3 text-sm"
                        value={settings.currency.code}
                        onChange={(e) => {
                          const code = e.target.value;
                          const selected = supportedCurrencies[code];
                          setSettings((s) => ({
                            ...s,
                            currency: {
                              code,
                              symbol: selected.symbol,
                              position: selected.position,
                            },
                          }));
                        }}
                      >
                        {Object.keys(supportedCurrencies).map((code) => (
                          <option key={code} value={code}>
                            {code}
                          </option>
                        ))}
                      </select>
                    </div>

                    {/* Symbol - auto-filled but editable */}
                    <div className="grid gap-2">
                      <Label htmlFor="currencySymbol">Symbol</Label>
                      <Input
                        id="currencySymbol"
                        value={settings.currency.symbol}
                        onChange={(e) =>
                          setSettings((s) => ({
                            ...s,
                            currency: { ...s.currency, symbol: e.target.value },
                          }))
                        }
                      />
                    </div>

                    {/* Position */}
                    <div className="grid gap-2">
                      <Label htmlFor="currencyPosition">Position</Label>
                      <select
                        id="currencyPosition"
                        className="h-10 rounded-md border px-3 text-sm"
                        value={settings.currency.position}
                        onChange={(e) =>
                          setSettings((s) => ({
                            ...s,
                            currency: {
                              ...s.currency,
                              position: e.target.value,
                            },
                          }))
                        }
                      >
                        <option value="prefix">Prefix</option>
                        <option value="suffix">Suffix</option>
                      </select>
                    </div>
                  </div>

                  {/* Fees */}
                  <div className="grid gap-3 sm:grid-cols-3">
                    <div className="grid gap-2">
                      <Label htmlFor="commissionPercent">Commission %</Label>
                      <Input
                        id="commissionPercent"
                        type="number"
                        value={settings.commissionPercent}
                        onChange={(e) =>
                          setSettings((s) => ({
                            ...s,
                            commissionPercent: e.target.value,
                          }))
                        }
                      />
                    </div>
                    <div className="grid gap-2">
                      <Label htmlFor="taxPercent">Tax %</Label>
                      <Input
                        id="taxPercent"
                        type="number"
                        value={settings.taxPercent}
                        onChange={(e) =>
                          setSettings((s) => ({
                            ...s,
                            taxPercent: e.target.value,
                          }))
                        }
                      />
                    </div>
                    <div className="grid gap-2">
                      <Label htmlFor="payoutThreshold">Payout Threshold</Label>
                      <Input
                        id="payoutThreshold"
                        type="number"
                        value={settings.payoutThreshold}
                        onChange={(e) =>
                          setSettings((s) => ({
                            ...s,
                            payoutThreshold: e.target.value,
                          }))
                        }
                      />
                    </div>
                  </div>

                  <Button type="submit" disabled={settingsSaving}>
                    {settingsSaving ? "Saving..." : "Save"}
                  </Button>
                </form>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
        <TabsContent value="basicInfo" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>Platform Info</CardTitle>
              <CardDescription>
                Manage branding and contact details.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={onSaveBasicInfo} className="space-y-4">
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="grid gap-2">
                    <Label htmlFor="platformName">Platform / Brand Name</Label>
                    <Input
                      id="platformName"
                      value={basicInfo.platformName}
                      onChange={(e) =>
                        setBasicInfo((s) => ({
                          ...s,
                          platformName: e.target.value,
                        }))
                      }
                      placeholder="e.g. EduMaster LMS"
                    />
                  </div>

                  <div className="grid gap-2">
                    <Label htmlFor="platformUrl">Website URL</Label>
                    <Input
                      id="platformUrl"
                      value={basicInfo.platformUrl}
                      onChange={(e) =>
                        setBasicInfo((s) => ({
                          ...s,
                          platformUrl: e.target.value,
                        }))
                      }
                      placeholder="https://yourdomain.com"
                    />
                  </div>
                </div>

                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="grid gap-2">
                    <Label htmlFor="contactEmail">Contact Email</Label>
                    <Input
                      id="contactEmail"
                      value={basicInfo.contactEmail}
                      onChange={(e) =>
                        setBasicInfo((s) => ({
                          ...s,
                          contactEmail: e.target.value,
                        }))
                      }
                    />
                  </div>

                  <div className="grid gap-2">
                    <Label htmlFor="supportPhone">Support Phone</Label>
                    <Input
                      id="supportPhone"
                      value={basicInfo.supportPhone}
                      onChange={(e) =>
                        setBasicInfo((s) => ({
                          ...s,
                          supportPhone: e.target.value,
                        }))
                      }
                    />
                  </div>
                </div>

                <div className="grid gap-2">
                  <Label htmlFor="address">Address</Label>
                  <Input
                    id="address"
                    value={basicInfo.address}
                    onChange={(e) =>
                      setBasicInfo((s) => ({ ...s, address: e.target.value }))
                    }
                  />
                </div>

                {/* Updated Logo Upload Section */}
                <div className="grid gap-2">
                  <Label htmlFor="logo">Brand Logo</Label>
                  <div className="flex items-center gap-4">
                    <Input
                      id="logo"
                      type="file"
                      accept="image/*"
                      onChange={handleLogoChange}
                      className="max-w-sm"
                    />
                    {logoFile && (
                      <Button
                        type="button"
                        variant="outline"
                        onClick={clearLogo}
                      >
                        Clear
                      </Button>
                    )}
                  </div>

                  {/* Logo Preview */}
                  {(logoPreview || basicInfo.branding.logoUrl) && (
                    <div className="mt-2">
                      <p className="text-sm text-muted-foreground mb-2">
                        Logo Preview:
                      </p>
                      <img
                        src={
                          // If it's a data URL (local file preview), use it directly
                          // Otherwise, use getMediaUrl for server URLs
                          logoPreview && logoPreview.startsWith("data:")
                            ? logoPreview
                            : getMediaUrl(
                                logoPreview || basicInfo.branding.logoUrl
                              )
                        }
                        alt="Logo preview"
                        className="h-16 rounded border object-contain"
                      />
                    </div>
                  )}
                  {/* Existing logo URL field (optional - you can remove this if you only want file upload) */}
                  {/* <div className="mt-2 grid gap-2">
                    <Label
                      htmlFor="logoUrl"
                      className="text-xs text-muted-foreground"
                    >
                      Or enter logo URL:
                    </Label>
                    <Input
                      id="logoUrl"
                      placeholder="https://example.com/logo.png"
                      value={basicInfo.branding.logoUrl}
                      onChange={(e) =>
                        setBasicInfo((s) => ({
                          ...s,
                          branding: { ...s.branding, logoUrl: e.target.value },
                        }))
                      }
                      className="text-sm"
                    />
                  </div> */}
                </div>

                <Button type="submit" disabled={basicSaving}>
                  {basicSaving ? "Saving..." : "Save Basic Info"}
                </Button>
              </form>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Email, Site, Features Tabs - unchanged */}
      </Tabs>
    </div>
  );
};

export default Settings;
