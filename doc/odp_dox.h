/* Copyright (c) 2013, Linaro Limited
 * All rights reserved
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @mainpage Open Data Plane
 *
 * @section sec_1 Introduction
 *
 * OpenDataPlane (ODP) provides a data plane application programming
 * environment that is easy to use, high performance, and portable
 * between networking SoCs. This documentation is both a user guide
 * for developers who wish to use ODP and a detailed reference for ODP
 * programmers covering APIs, data structures, files, etc.  It should
 * also be useful for those wishing to implement ODP on other
 * platforms.
 *
 *  @image html overview.png
 *
 * ODP consists of a common layer and an implementation layer.
 * Applications written to the common layer are portable across all
 * ODP implementations.  To compile and run an ODP application, it is
 * compiled against a specific ODP implementation layer.  The purpose
 * of the implementation layer is to provide an optimal mapping of ODP
 * APIs to the underlying capabilities (including hardware
 * co-processing and acceleration support) of of SoCs hosting ODP
 * implementations. This document has been generated from the ODP
 * source code version 1.4.1. Refer to the Todo List chapter for a
 * list of non-supported APIs on the QorIQ platform(s). API document
 * has been updated for additional feature(s) supported on QorIQ platform(s).
 * => Ipsec Protocol offload extensions – Refer section 5.8 ODP Crypto.
 *
 * @section contact Contact Details
 * - The ODP Open source web site is http://www.opendataplane.org/
 *
 */
