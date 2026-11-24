package io.supertokens.passkeysync;

import java.util.Locale;

public enum DeviceKind {
    DESKTOP,
    MOBILE,
    TABLET,
    OTHER;

    public static DeviceKind fromString(String value) throws PasskeySyncException {
        if (value == null || value.isBlank()) {
            throw new PasskeySyncException("INVALID_DEVICE_KIND", "deviceKind is required");
        }
        String normalized = value.trim().toUpperCase(Locale.ROOT).replace('-', '_').replace(' ', '_');
        try {
            return DeviceKind.valueOf(normalized);
        } catch (IllegalArgumentException e) {
            throw new PasskeySyncException("INVALID_DEVICE_KIND",
                    "deviceKind must be one of desktop, mobile, tablet, other");
        }
    }
}
