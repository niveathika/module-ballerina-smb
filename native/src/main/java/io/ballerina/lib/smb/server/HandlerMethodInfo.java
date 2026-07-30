/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package io.ballerina.lib.smb.server;

import io.ballerina.runtime.api.types.MethodType;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Resolved, immutable metadata for a single service remote function, computed once at
 * service registration (attach) time and reused for every subsequent dispatch.
 *
 * + method - the resolved {@code MethodType} of the remote function
 * + pattern - the effective compiled file name pattern (method-level {@code @FunctionConfig}
 *             falling back to the listener-level pattern), or {@code null} when no pattern applies
 * + afterProcess - the parsed post-process action to run after a successful invocation, if any
 * + afterError - the parsed post-process action to run after a failed invocation, if any
 * + extraParams - the ordered list of recognized trailing parameter roles ({@code FileInfo}/{@code Caller})
 *                 declared on the method, in declaration order
 * + isolatedMethod - whether the method can be safely dispatched on a concurrent strand
 */
record HandlerMethodInfo(MethodType method, Pattern pattern, PostProcessAction afterProcess,
                          PostProcessAction afterError, List<String> extraParams, boolean isolatedMethod) {

    boolean matchesFileName(String fileName) {
        if (pattern == null) {
            return true;
        }
        return pattern.matcher(fileName).matches();
    }
}
