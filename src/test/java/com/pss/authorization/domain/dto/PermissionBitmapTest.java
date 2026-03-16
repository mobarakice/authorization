package com.pss.authorization.domain.dto;

import org.junit.jupiter.api.Test;

import java.util.BitSet;

import static org.assertj.core.api.Assertions.assertThat;

class PermissionBitmapTest {

    private PermissionBitmap bitmapWith(int... setBits) {
        BitSet bits = new BitSet();
        for (int b : setBits) bits.set(b);
        return PermissionBitmap.builder()
                .subjectId((long)(Math.random() * 10000L))
                .tenantId("tenant1")
                .permissions(bits)
                .version(1L)
                .computedAt(System.currentTimeMillis())
                .build();
    }

    // --- hasPermission ---

    @Test
    void hasPermission_bitSet_returnsTrue() {
        assertThat(bitmapWith(5, 10, 20).hasPermission(10)).isTrue();
    }

    @Test
    void hasPermission_bitNotSet_returnsFalse() {
        assertThat(bitmapWith(5, 10).hasPermission(20)).isFalse();
    }

    @Test
    void hasPermission_zeroBit_returnsTrue() {
        assertThat(bitmapWith(0, 1).hasPermission(0)).isTrue();
    }

    @Test
    void hasPermission_nullPermissions_returnsFalse() {
        PermissionBitmap bitmap = PermissionBitmap.builder()
                .subjectId((long)(Math.random() * 10000L))
                .tenantId("t1")
                .permissions(null)
                .build();
        assertThat(bitmap.hasPermission(0)).isFalse();
    }

    @Test
    void hasPermission_emptyBitmap_returnsFalse() {
        assertThat(bitmapWith().hasPermission(10)).isFalse();
    }

    // --- hasAnyPermission ---

    @Test
    void hasAnyPermission_oneMatch_returnsTrue() {
        assertThat(bitmapWith(5, 10).hasAnyPermission(10, 20, 30)).isTrue();
    }

    @Test
    void hasAnyPermission_firstMatch_returnsTrue() {
        assertThat(bitmapWith(5, 10).hasAnyPermission(5, 20)).isTrue();
    }

    @Test
    void hasAnyPermission_noMatch_returnsFalse() {
        assertThat(bitmapWith(5, 10).hasAnyPermission(20, 30)).isFalse();
    }

    @Test
    void hasAnyPermission_nullPermissions_returnsFalse() {
        PermissionBitmap bitmap = PermissionBitmap.builder()
                .subjectId((long)(Math.random() * 10000L))
                .tenantId("t1")
                .permissions(null)
                .build();
        assertThat(bitmap.hasAnyPermission(0, 1, 2)).isFalse();
    }

    // --- hasAllPermissions ---

    @Test
    void hasAllPermissions_allMatch_returnsTrue() {
        assertThat(bitmapWith(5, 10, 15).hasAllPermissions(5, 10)).isTrue();
    }

    @Test
    void hasAllPermissions_exactMatch_returnsTrue() {
        assertThat(bitmapWith(5, 10).hasAllPermissions(5, 10)).isTrue();
    }

    @Test
    void hasAllPermissions_oneMissing_returnsFalse() {
        assertThat(bitmapWith(5, 10).hasAllPermissions(5, 10, 15)).isFalse();
    }

    @Test
    void hasAllPermissions_emptyBitmap_returnsFalse() {
        assertThat(bitmapWith().hasAllPermissions(5)).isFalse();
    }

    @Test
    void hasAllPermissions_nullPermissions_returnsFalse() {
        PermissionBitmap bitmap = PermissionBitmap.builder()
                .subjectId((long)(Math.random() * 10000L))
                .tenantId("t1")
                .permissions(null)
                .build();
        assertThat(bitmap.hasAllPermissions(0)).isFalse();
    }

    // --- permissionCount ---

    @Test
    void permissionCount_fourBitsSet_returns4() {
        assertThat(bitmapWith(0, 1, 2, 3).permissionCount()).isEqualTo(4);
    }

    @Test
    void permissionCount_emptyBitmap_returnsZero() {
        assertThat(bitmapWith().permissionCount()).isEqualTo(0);
    }

    @Test
    void permissionCount_nullPermissions_returnsZero() {
        PermissionBitmap bitmap = PermissionBitmap.builder()
                .subjectId((long)(Math.random() * 10000L))
                .tenantId("t1")
                .permissions(null)
                .build();
        assertThat(bitmap.permissionCount()).isEqualTo(0);
    }

    @Test
    void permissionCount_highBitIndex_countedCorrectly() {
        assertThat(bitmapWith(43, 44, 45).permissionCount()).isEqualTo(3);
    }
}
