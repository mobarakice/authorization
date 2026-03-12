package com.pss.authorization.domain.model.abac;

/**
 * Category of an attribute definition.
 * Based on XACML attribute categories.
 */
public enum AttributeCategory {

    /**
     * Attributes about the subject (user/service) making the request.
     */
    SUBJECT,

    /**
     * Attributes about the resource being accessed.
     */
    RESOURCE,

    /**
     * Attributes about the action being performed.
     */
    ACTION,

    /**
     * Environmental attributes (time, location, IP, etc.).
     */
    ENVIRONMENT
}
