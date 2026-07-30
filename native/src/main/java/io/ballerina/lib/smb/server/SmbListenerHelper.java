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

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.auth.GSSAuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;
import io.ballerina.lib.smb.client.SmbClient;
import io.ballerina.lib.smb.iterator.ByteIterator;
import io.ballerina.lib.smb.iterator.CsvIterator;
import io.ballerina.lib.smb.util.ModuleUtils;
import io.ballerina.lib.smb.util.SmbContentConverter;
import io.ballerina.lib.smb.util.SmbUtil;
import io.ballerina.runtime.api.Environment;
import io.ballerina.runtime.api.concurrent.StrandMetadata;
import io.ballerina.runtime.api.creators.ErrorCreator;
import io.ballerina.runtime.api.creators.TypeCreator;
import io.ballerina.runtime.api.creators.ValueCreator;
import io.ballerina.runtime.api.types.ArrayType;
import io.ballerina.runtime.api.types.MethodType;
import io.ballerina.runtime.api.types.ObjectType;
import io.ballerina.runtime.api.types.Parameter;
import io.ballerina.runtime.api.types.PredefinedTypes;
import io.ballerina.runtime.api.types.ServiceType;
import io.ballerina.runtime.api.types.StreamType;
import io.ballerina.runtime.api.types.TupleType;
import io.ballerina.runtime.api.types.Type;
import io.ballerina.runtime.api.types.TypeTags;
import io.ballerina.runtime.api.utils.JsonUtils;
import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.utils.TypeUtils;
import io.ballerina.runtime.api.values.BArray;
import io.ballerina.runtime.api.values.BError;
import io.ballerina.runtime.api.values.BMap;
import io.ballerina.runtime.api.values.BObject;
import io.ballerina.runtime.api.values.BString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import static io.ballerina.lib.smb.client.SmbClient.ACCESSED_AT;
import static io.ballerina.lib.smb.client.SmbClient.CREATED_AT;
import static io.ballerina.lib.smb.client.SmbClient.EXTENSION;
import static io.ballerina.lib.smb.client.SmbClient.IS_DIRECTORY;
import static io.ballerina.lib.smb.client.SmbClient.IS_EXECUTABLE;
import static io.ballerina.lib.smb.client.SmbClient.IS_HIDDEN;
import static io.ballerina.lib.smb.client.SmbClient.IS_WRITABLE;
import static io.ballerina.lib.smb.client.SmbClient.MISSING_CREDENTIALS_FOR_AUTH_ERROR;
import static io.ballerina.lib.smb.client.SmbClient.MODIFIED_AT;
import static io.ballerina.lib.smb.client.SmbClient.NAME;
import static io.ballerina.lib.smb.client.SmbClient.PATH;
import static io.ballerina.lib.smb.client.SmbClient.SMB_ERROR;
import static io.ballerina.lib.smb.client.SmbClient.URI;
import static io.ballerina.lib.smb.client.SmbClient.WRITTEN_AT;

/**
 * Helper class for SMB listener operations.
 */
public class SmbListenerHelper {
    private static final Logger log = LoggerFactory.getLogger(SmbListenerHelper.class);
    private static final int ARRAY_SIZE = 65536;
    private static final Set<String> EXECUTABLE_EXTENSIONS = Set.of(
            "exe", "bat", "cmd", "com", "msi", "ps1", "vbs", "wsf", "jar"
    );
    public static final String ENDPOINT_CONFIG_HOST = "host";
    public static final String ENDPOINT_CONFIG_SHARE = "share";
    public static final String ENDPOINT_CONFIG_PORT = "port";
    public static final String ENDPOINT_CONFIG_USERNAME = "username";
    public static final String ENDPOINT_CONFIG_PASS_KEY = "password";
    public static final String ENDPOINT_CONFIG_DOMAIN = "domain";
    public static final String ENDPOINT_CONFIG_AUTH = "auth";
    public static final String ENDPOINT_CONFIG_CREDENTIALS = "credentials";
    public static final String KERBEROS_CONFIG = "kerberosConfig";
    public static final String KERBEROS_PRINCIPAL = "principal";
    public static final String KERBEROS_KEYTAB = "keytab";
    public static final String KERBEROS_CONFIG_FILE = "configFile";
    public static final String KERBEROS_AUTH_CONTEXT_ERROR = "Failed to create Kerberos authentication context: ";
    public static final String MISSING_CREDENTIALS_FOR_KERBEROS_ERROR =
            "Credentials with password must be provided for Kerberos authentication when keytab is not specified";
    private static final String LISTENER_SERVICES = "LISTENER_SERVICES";
    private static final String LISTENER_PREVIOUS_FILES = "LISTENER_PREVIOUS_FILES";
    private static final String LISTENER_SMB_CLIENT = "LISTENER_SMB_CLIENT";
    private static final String LISTENER_CONNECTION = "LISTENER_CONNECTION";
    private static final String LISTENER_SESSION = "LISTENER_SESSION";
    private static final String LISTENER_DISK_SHARE = "LISTENER_DISK_SHARE";
    private static final String LISTENER_CALLER = "LISTENER_CALLER";
    private static final String LISTENER_CALLER_CLIENT = "LISTENER_CALLER_CLIENT";
    public static final String SMB_SERVICE_ENDPOINT_CONFIG = "serviceEndpointConfig";
    private static final String ON_FILE_TEXT = "onFileText";
    private static final String ON_FILE_JSON = "onFileJson";
    private static final String ON_FILE_XML = "onFileXml";
    private static final String ON_FILE_CSV = "onFileCsv";
    private static final String ON_FILE = "onFile";
    private static final String ON_FILE_DELETE = "onFileDelete";
    private static final String EXT_TXT = "txt";
    private static final String EXT_LOG = "log";
    private static final String EXT_MD = "md";
    private static final String EXT_JSON = "json";
    private static final String EXT_XML = "xml";
    private static final String EXT_CSV = "csv";
    private static final String FUNCTION_CONFIG = "FunctionConfig";
    private static final String SERVICE_CONFIG = "ServiceConfig";
    private static final String PATH_KEY = "path";
    private static final String FILE_NAME_PATTERN = "fileNamePattern";
    private static final String AFTER_PROCESS = "afterProcess";
    private static final String AFTER_ERROR = "afterError";
    private static final String MOVE_TO = "moveTo";
    private static final String PRESERVE_SUB_DIRS = "preserveSubDirs";
    private static final String FILE_INFO = "FileInfo";
    public static final String INITIALIZE_SMB_LISTENER_ERROR = "Failed to initialize SMB listener: ";
    public static final String DEREGISTER_SERVICE_ERROR = "Failed to deregister service: ";
    public static final String SLASH_SUFFIX = "/";
    public static final String ON_ERROR_METHOD = "onError";
    public static final String POLLING_ERROR = "Failed to start polling files: ";
    public static final String COLON = ":";
    public static final String CALLER = "Caller";
    public static final String PARSE_XML_CONTENT_ERROR = "Failed to parse XML content: ";
    public static final String CSV_PARSE_ERROR = "Failed to parse CSV content: ";
    public static final String JSON_PARSE_ERROR = "Failed to parse JSON: ";
    public static final String FILE_READ_ERROR = "Failed to read file: ";
    public static final String CLIENT = "Client";
    public static final String REGISTER_SERVICE_ERROR = "Failed to register service: ";
    public static final String LISTENER_NOT_INITIALIZED_ERROR = "Listener is not initialized";
    public static final String ENDPOINT_CONFIG_CSV_FAIL_SAFE = "csvFailSafe";
    public static final String ENDPOINT_CONFIG_LAX_DATA_BINDING = "laxDataBinding";
    public static final BString SIZE = StringUtils.fromString("size");
    private static final List<String> CONTENT_HANDLER_METHOD_NAMES =
            List.of(ON_FILE_TEXT, ON_FILE_JSON, ON_FILE_XML, ON_FILE_CSV, ON_FILE);
    private static final Pattern NEVER_MATCH_PATTERN = Pattern.compile("(?!)");

    private SmbListenerHelper() {
    }

    private static boolean isExecutableFile(String fileName) {
        int lastDot = fileName.lastIndexOf('.');
        if (lastDot <= 0) {
            return false;
        }
        String extension = fileName.substring(lastDot + 1).toLowerCase();
        return EXECUTABLE_EXTENSIONS.contains(extension);
    }

    public static Object init(BObject listenerEndpoint, BMap<BString, Object> config) {
        try {
            listenerEndpoint.addNativeData(SMB_SERVICE_ENDPOINT_CONFIG, config);
            List<SmbService> services = new ArrayList<>();
            listenerEndpoint.addNativeData(LISTENER_SERVICES, services);
            Map<String, Set<String>> previousFiles = new HashMap<>();
            listenerEndpoint.addNativeData(LISTENER_PREVIOUS_FILES, previousFiles);
            return null;
        } catch (Exception e) {
            return SmbUtil.createError(INITIALIZE_SMB_LISTENER_ERROR + e.getMessage(), SMB_ERROR);
        }
    }

    public static Object register(BObject listenerEndpoint, BObject smbService, Object name) {
        try {
            List<SmbService> services =
                (List<SmbService>) listenerEndpoint.getNativeData(LISTENER_SERVICES);
            if (services == null) {
                return SmbUtil.createError(LISTENER_NOT_INITIALIZED_ERROR, SMB_ERROR);
            }
            String path = getServicePath(smbService, name);
            path = normalizePath(path);
            ObjectType serviceType = (ObjectType) TypeUtils.getReferredType(TypeUtils.getType(smbService));
            BMap<BString, Object> listenerConfig =
                (BMap<BString, Object>) listenerEndpoint.getNativeData(SMB_SERVICE_ENDPOINT_CONFIG);
            Map<String, HandlerMethodInfo> handlers = buildHandlerMetadata(serviceType, listenerConfig);
            SmbService registration = new SmbService(smbService, path, serviceType, handlers);
            services.add(registration);
            return null;
        } catch (Exception e) {
            return SmbUtil.createError(REGISTER_SERVICE_ERROR + e.getMessage(), SMB_ERROR);
        }
    }

    private static Map<String, HandlerMethodInfo> buildHandlerMetadata(ObjectType serviceType,
                                                                        BMap<BString, Object> listenerConfig) {
        Map<String, HandlerMethodInfo> handlers = new HashMap<>();
        for (String methodName : CONTENT_HANDLER_METHOD_NAMES) {
            MethodType method = getMethod(serviceType, methodName);
            if (method != null) {
                handlers.put(methodName,
                        buildHandlerMethodInfo(serviceType, method, methodName, listenerConfig, true));
            }
        }
        MethodType deleteMethod = getMethod(serviceType, ON_FILE_DELETE);
        if (deleteMethod != null) {
            handlers.put(ON_FILE_DELETE,
                    buildHandlerMethodInfo(serviceType, deleteMethod, ON_FILE_DELETE, listenerConfig, false));
        }
        return handlers;
    }

    private static HandlerMethodInfo buildHandlerMethodInfo(ObjectType serviceType, MethodType method,
                                                             String methodName, BMap<BString, Object> listenerConfig,
                                                             boolean includeFileInfo) {
        BMap<BString, Object> annotation = getFunctionConfigAnnotation(method);
        PostProcessAction afterProcess = parsePostProcessAction(annotation, AFTER_PROCESS);
        PostProcessAction afterError = parsePostProcessAction(annotation, AFTER_ERROR);
        Pattern pattern = compileEffectivePattern(annotation, listenerConfig);
        List<String> extraParams = computeExtraParams(method, includeFileInfo);
        boolean isolatedMethod = serviceType.isIsolated() && serviceType.isIsolated(methodName);
        return new HandlerMethodInfo(method, pattern, afterProcess, afterError, extraParams, isolatedMethod);
    }

    private static Pattern compileEffectivePattern(BMap<BString, Object> annotation,
                                                    BMap<BString, Object> listenerConfig) {
        String patternStr = null;
        if (annotation != null) {
            BString patternValue = annotation.getStringValue(StringUtils.fromString(FILE_NAME_PATTERN));
            if (patternValue != null) {
                patternStr = patternValue.getValue();
            }
        }
        if (patternStr == null && listenerConfig != null) {
            BString listenerPatternValue = listenerConfig.getStringValue(StringUtils.fromString(FILE_NAME_PATTERN));
            if (listenerPatternValue != null) {
                patternStr = listenerPatternValue.getValue();
            }
        }
        if (patternStr == null) {
            return null;
        }
        try {
            return Pattern.compile(patternStr);
        } catch (Exception e) {
            log.debug("Invalid fileNamePattern '{}': {}", patternStr, e.getMessage());
            return NEVER_MATCH_PATTERN;
        }
    }

    private static List<String> computeExtraParams(MethodType method, boolean includeFileInfo) {
        List<String> extraParams = new ArrayList<>();
        Parameter[] parameters = method.getParameters();
        for (int i = 1; i < parameters.length; i++) {
            Type paramType = TypeUtils.getReferredType(parameters[i].type);
            String paramTypeName = paramType.getName();
            if (includeFileInfo && FILE_INFO.equals(paramTypeName)) {
                extraParams.add(FILE_INFO);
            } else if (CALLER.equals(paramTypeName)) {
                extraParams.add(CALLER);
            }
        }
        return extraParams;
    }

    private static String getServicePath(BObject smbService, Object name) {
        Type serviceType = TypeUtils.getReferredType(TypeUtils.getType(smbService));
        if (serviceType instanceof ServiceType) {
            BMap<BString, Object> serviceConfig = getServiceConfig((ServiceType) serviceType);
            if (serviceConfig != null) {
                BString pathValue = serviceConfig.getStringValue(StringUtils.fromString(PATH_KEY));
                if (pathValue != null && !pathValue.getValue().isEmpty()) {
                    return pathValue.getValue();
                }
            }
        }
        if (name == null) {
            return SLASH_SUFFIX;
        }
        return ((BString) name).getValue();
    }

    private static BMap<BString, Object> getServiceConfig(ServiceType serviceType) {
        BString packageName = StringUtils.fromString(ModuleUtils.getModule().toString());
        BString serviceConfigName = StringUtils.fromString(SERVICE_CONFIG);
        Object annotation = serviceType.getAnnotation(packageName, serviceConfigName);
        if (annotation == null) {
            return null;
        }
        return (BMap<BString, Object>) annotation;
    }

    private static String normalizePath(String path) {
        if (path == null || path.isEmpty()) {
            return SLASH_SUFFIX;
        }
        if (!path.startsWith(SLASH_SUFFIX)) {
            path = SLASH_SUFFIX + path;
        }
        if (path.length() > 1 && path.endsWith(SLASH_SUFFIX)) {
            path = path.substring(0, path.length() - 1);
        }
        return path;
    }

    public static Object deregister(BObject listenerEndpoint, BObject smbService) {
        try {
            List<SmbService> services =
                (List<SmbService>) listenerEndpoint.getNativeData(LISTENER_SERVICES);
            if (services != null) {
                services.removeIf(registration -> registration.service().equals(smbService));
            }
            return null;
        } catch (Exception e) {
            return SmbUtil.createError(DEREGISTER_SERVICE_ERROR + e.getMessage(), SMB_ERROR);
        }
    }

    public static Object poll(Environment env, BObject listenerEndpoint) {
        return env.yieldAndRun(() -> {
            try {
                BMap<BString, Object> config =
                    (BMap<BString, Object>) listenerEndpoint.getNativeData(SMB_SERVICE_ENDPOINT_CONFIG);
                checkForFileChanges(env, listenerEndpoint, config);
                return null;
            } catch (Exception e) {
                List<SmbService> services =
                    (List<SmbService>) listenerEndpoint.getNativeData(LISTENER_SERVICES);
                notifyServicesOnError(env, services, e);
                return SmbUtil.createError(POLLING_ERROR + e.getMessage(), SMB_ERROR);
            }
        });
    }

    public static Object cleanup(BObject listenerEndpoint) throws Exception {
        closeExistingResources(listenerEndpoint);
        List<SmbService> services =
            (List<SmbService>) listenerEndpoint.getNativeData(LISTENER_SERVICES);
        if (services != null) {
            services.clear();
        }
        Map<String, Set<String>> previousFiles =
            (Map<String, Set<String>>) listenerEndpoint.getNativeData(LISTENER_PREVIOUS_FILES);
        if (previousFiles != null) {
            previousFiles.clear();
        }
        return null;
    }

    private static void checkForFileChanges(Environment env, BObject listenerEndpoint,
                                            BMap<BString, Object> config) throws Exception {
        DiskShare diskShare = getOrCreateDiskShare(listenerEndpoint, config);
        List<SmbService> services =
                (List<SmbService>) listenerEndpoint.getNativeData(LISTENER_SERVICES);
        if (services == null || services.isEmpty()) {
            return;
        }
        List<SmbService> smbServices = new ArrayList<>(services);
        Set<String> pathsToMonitor = new HashSet<>();
        for (SmbService registration : smbServices) {
            pathsToMonitor.add(registration.path());
        }
        for (String path : pathsToMonitor) {
            checkPathForChanges(env, listenerEndpoint, diskShare, path, smbServices, config);
        }
    }

    private static DiskShare getOrCreateDiskShare(BObject listenerEndpoint,
                                                   BMap<BString, Object> config) throws Exception {
        DiskShare existingShare = (DiskShare) listenerEndpoint.getNativeData(LISTENER_DISK_SHARE);
        Connection existingConnection = (Connection) listenerEndpoint.getNativeData(LISTENER_CONNECTION);
        if (existingShare != null && existingConnection != null && existingConnection.isConnected()) {
            return existingShare;
        }
        closeExistingResources(listenerEndpoint);
        String host = config.getStringValue(StringUtils.fromString(ENDPOINT_CONFIG_HOST)).getValue();
        String share = config.getStringValue(StringUtils.fromString(ENDPOINT_CONFIG_SHARE)).getValue();
        int port = config.getIntValue(StringUtils.fromString(ENDPOINT_CONFIG_PORT)).intValue();
        BMap<?, ?> authConfig = config.getMapValue(StringUtils.fromString(ENDPOINT_CONFIG_AUTH));
        AuthenticationContext authContext = createAuthContext(authConfig);
        SMBClient smbClient = new SMBClient();
        Connection connection = smbClient.connect(host, port);
        Session session = connection.authenticate(authContext);
        DiskShare diskShare = (DiskShare) session.connectShare(share);
        listenerEndpoint.addNativeData(LISTENER_SMB_CLIENT, smbClient);
        listenerEndpoint.addNativeData(LISTENER_CONNECTION, connection);
        listenerEndpoint.addNativeData(LISTENER_SESSION, session);
        listenerEndpoint.addNativeData(LISTENER_DISK_SHARE, diskShare);
        return diskShare;
    }

    private static AuthenticationContext createAuthContext(BMap<?, ?> authConfig) throws Exception {
        if (authConfig == null) {
            return AuthenticationContext.anonymous();
        }
        BMap<?, ?> credentials = authConfig.getMapValue(StringUtils.fromString(ENDPOINT_CONFIG_CREDENTIALS));
        BMap<?, ?> kerberosConfig = authConfig.getMapValue(StringUtils.fromString(KERBEROS_CONFIG));
        if (credentials == null && kerberosConfig == null) {
            throw new Exception(MISSING_CREDENTIALS_FOR_AUTH_ERROR);
        }
        if (kerberosConfig != null && credentials == null) {
            BString keytabValue = kerberosConfig.getStringValue(StringUtils.fromString(KERBEROS_KEYTAB));
            boolean hasKeytab = keytabValue != null && !keytabValue.getValue().isEmpty();
            if (!hasKeytab) {
                throw new Exception(MISSING_CREDENTIALS_FOR_KERBEROS_ERROR);
            }
        }
        if (kerberosConfig != null) {
            BString keytabValue = kerberosConfig.getStringValue(StringUtils.fromString(KERBEROS_KEYTAB));
            boolean hasKeytab = keytabValue != null && !keytabValue.getValue().isEmpty();
            if (!hasKeytab && credentials == null) {
                throw new RuntimeException(MISSING_CREDENTIALS_FOR_KERBEROS_ERROR);
            }
            String password = null;
            String domain = null;
            if (credentials != null) {
                BString passwordBStr = credentials.getStringValue(StringUtils.fromString(ENDPOINT_CONFIG_PASS_KEY));
                password = passwordBStr != null ? passwordBStr.getValue() : null;
                BString domainBStr = credentials.getStringValue(StringUtils.fromString(ENDPOINT_CONFIG_DOMAIN));
                domain = domainBStr != null ? domainBStr.getValue() : null;
            }
            return createKerberosAuthContext(kerberosConfig, password, domain);
        }
        String username =
                credentials.getStringValue(StringUtils.fromString(ENDPOINT_CONFIG_USERNAME)).getValue();
        String password =
                credentials.getStringValue(StringUtils.fromString(ENDPOINT_CONFIG_PASS_KEY)).getValue();
        BString domainBStr = credentials.getStringValue(StringUtils.fromString(ENDPOINT_CONFIG_DOMAIN));
        String domain = domainBStr != null ? domainBStr.getValue() : null;
        return new AuthenticationContext(
                username,
                password != null ? password.toCharArray() : new char[0],
                domain
        );
    }

    private static void closeExistingResources(BObject listenerEndpoint) throws Exception {
        DiskShare diskShare = (DiskShare) listenerEndpoint.getNativeData(LISTENER_DISK_SHARE);
        Session session = (Session) listenerEndpoint.getNativeData(LISTENER_SESSION);
        Connection connection = (Connection) listenerEndpoint.getNativeData(LISTENER_CONNECTION);
        SMBClient smbClient = (SMBClient) listenerEndpoint.getNativeData(LISTENER_SMB_CLIENT);
        closeQuietly(diskShare);
        closeQuietly(session);
        closeQuietly(connection);
        closeQuietly(smbClient);
        listenerEndpoint.addNativeData(LISTENER_DISK_SHARE, null);
        listenerEndpoint.addNativeData(LISTENER_SESSION, null);
        listenerEndpoint.addNativeData(LISTENER_CONNECTION, null);
        listenerEndpoint.addNativeData(LISTENER_SMB_CLIENT, null);
        closeCachedCaller(listenerEndpoint);
    }

    private static void closeQuietly(AutoCloseable closeable) throws Exception {
        if (closeable != null) {
            closeable.close();
        }
    }

    private static BObject getOrCreateCaller(BObject listenerEndpoint, BMap<BString, Object> listenerConfig) {
        BObject cachedCaller = (BObject) listenerEndpoint.getNativeData(LISTENER_CALLER);
        if (cachedCaller != null && isCallerConnectionOpen(listenerEndpoint)) {
            return cachedCaller;
        }
        synchronized (listenerEndpoint) {
            cachedCaller = (BObject) listenerEndpoint.getNativeData(LISTENER_CALLER);
            if (cachedCaller != null && isCallerConnectionOpen(listenerEndpoint)) {
                return cachedCaller;
            }
            try {
                BObject client = ValueCreator.createObjectValue(ModuleUtils.getModule(), CLIENT, listenerConfig);
                BObject caller = ValueCreator.createObjectValue(ModuleUtils.getModule(), CALLER, client);
                listenerEndpoint.addNativeData(LISTENER_CALLER_CLIENT, client);
                listenerEndpoint.addNativeData(LISTENER_CALLER, caller);
                return caller;
            } catch (Exception e) {
                log.debug("Failed to create SMB caller: {}", e.getMessage());
                return null;
            }
        }
    }

    private static boolean isCallerConnectionOpen(BObject listenerEndpoint) {
        BObject cachedClient = (BObject) listenerEndpoint.getNativeData(LISTENER_CALLER_CLIENT);
        return cachedClient != null && cachedClient.getNativeData(SmbClient.SMB_CONNECTION) != null;
    }

    private static void closeCachedCaller(BObject listenerEndpoint) {
        BObject cachedClient = (BObject) listenerEndpoint.getNativeData(LISTENER_CALLER_CLIENT);
        if (cachedClient != null) {
            Object result = SmbClient.close(cachedClient);
            if (result instanceof BError bError) {
                log.debug("Failed to close cached SMB caller: {}", bError.getErrorMessage().getValue());
            }
        }
        listenerEndpoint.addNativeData(LISTENER_CALLER_CLIENT, null);
        listenerEndpoint.addNativeData(LISTENER_CALLER, null);
    }

    private static void checkPathForChanges(Environment env, BObject listenerEndpoint, DiskShare diskShare,
                                           String path, List<SmbService> allServices,
                                           BMap<BString, Object> listenerConfig) {
        Map<String, Set<String>> previousFiles =
                (Map<String, Set<String>>) listenerEndpoint.getNativeData(LISTENER_PREVIOUS_FILES);
        Set<String> prevFiles = new HashSet<>(previousFiles.getOrDefault(path, new HashSet<>()));

        Map<String, FileIdBothDirectoryInformation> currentFileInfos = new LinkedHashMap<>();
        collectFilesRecursively(diskShare, path, currentFileInfos);
        Set<String> currentFiles = new HashSet<>(currentFileInfos.keySet());

        for (String prevFile : prevFiles) {
            if (currentFiles.contains(prevFile)) {
                String normalizedPath = prevFile.startsWith(SLASH_SUFFIX) ? prevFile.substring(1) : prevFile;
                if (!diskShare.fileExists(normalizedPath)) {
                    currentFiles.remove(prevFile);
                }
            }
        }

        List<BMap<BString, Object>> addedFiles = new ArrayList<>();
        for (Map.Entry<String, FileIdBothDirectoryInformation> entry : currentFileInfos.entrySet()) {
            String fileKey = entry.getKey();
            if (!prevFiles.contains(fileKey)) {
                String parentPath = fileKey.contains(SLASH_SUFFIX)
                        ? fileKey.substring(0, fileKey.lastIndexOf(SLASH_SUFFIX))
                        : path;
                addedFiles.add(createFileInfoRecord(entry.getValue(), parentPath));
            }
        }

        List<String> deletedFiles = new ArrayList<>();
        for (String prevFile : prevFiles) {
            if (!currentFiles.contains(prevFile)) {
                deletedFiles.add(prevFile);
            }
        }

        previousFiles.put(path, new HashSet<>(currentFiles));
        if (!addedFiles.isEmpty()) {
            notifyServicesForPath(env, listenerEndpoint, path, addedFiles, allServices, diskShare, listenerConfig);
        }
        if (!deletedFiles.isEmpty()) {
            notifyServicesForDeletedFiles(env, listenerEndpoint, path, deletedFiles, allServices, listenerConfig);
        }
    }

    private static void collectFilesRecursively(DiskShare diskShare, String path,
                                                Map<String, FileIdBothDirectoryInformation> result) {
        String listPath = path.startsWith(SLASH_SUFFIX) ? path.substring(1) : path;
        List<FileIdBothDirectoryInformation> files = diskShare.list(listPath);
        for (FileIdBothDirectoryInformation fileInfo : files) {
            String fileName = fileInfo.getFileName();
            if (".".equals(fileName) || "..".equals(fileName)) {
                continue;
            }
            boolean isFolder = EnumWithValue.EnumUtils.isSet(
                    fileInfo.getFileAttributes(), FileAttributes.FILE_ATTRIBUTE_DIRECTORY);
            String fileKey = path.endsWith(SLASH_SUFFIX) ? path + fileName : path + SLASH_SUFFIX + fileName;
            if (isFolder) {
                try {
                    collectFilesRecursively(diskShare, fileKey, result);
                } catch (Exception e) {
                    log.debug("Skipping folder '{}' during recursive listing (may have been deleted): {}",
                            fileKey, e.getMessage());
                }
            } else {
                result.put(fileKey, fileInfo);
            }
        }
    }

    private static BMap<BString, Object> createFileInfoRecord(FileIdBothDirectoryInformation fileInfo,
                                                              String basePath) {
        BMap<BString, Object> fileInfoRecord = ValueCreator.createRecordValue(ModuleUtils.getModule(), FILE_INFO);
        String fileName = fileInfo.getFileName();
        String fullPath = basePath;
        if (!fullPath.endsWith(SLASH_SUFFIX)) {
            fullPath += SLASH_SUFFIX;
        }
        fullPath += fileName;

        long fileAttributes = fileInfo.getFileAttributes();
        boolean isFolder = EnumWithValue.EnumUtils.isSet(fileAttributes, FileAttributes.FILE_ATTRIBUTE_DIRECTORY);
        boolean isHidden = EnumWithValue.EnumUtils.isSet(fileAttributes, FileAttributes.FILE_ATTRIBUTE_HIDDEN);
        boolean isReadOnly = EnumWithValue.EnumUtils.isSet(fileAttributes, FileAttributes.FILE_ATTRIBUTE_READONLY);

        int lastDot = fileName.lastIndexOf('.');
        String extension = lastDot > 0 ? fileName.substring(lastDot + 1) : "";

        boolean isExecutable = !isFolder && isExecutableFile(fileName);

        fileInfoRecord.put(NAME, StringUtils.fromString(fileName));
        fileInfoRecord.put(PATH, StringUtils.fromString(fullPath));
        fileInfoRecord.put(SIZE, fileInfo.getEndOfFile());
        fileInfoRecord.put(MODIFIED_AT, createUtcTuple(fileInfo.getChangeTime().toEpochMillis()));
        fileInfoRecord.put(CREATED_AT, createUtcTuple(fileInfo.getCreationTime().toEpochMillis()));
        fileInfoRecord.put(ACCESSED_AT, createUtcTuple(fileInfo.getLastAccessTime().toEpochMillis()));
        fileInfoRecord.put(WRITTEN_AT, createUtcTuple(fileInfo.getLastWriteTime().toEpochMillis()));
        fileInfoRecord.put(IS_DIRECTORY, isFolder);
        fileInfoRecord.put(EXTENSION, StringUtils.fromString(extension));
        fileInfoRecord.put(IS_EXECUTABLE, isExecutable);
        fileInfoRecord.put(IS_HIDDEN, isHidden);
        fileInfoRecord.put(IS_WRITABLE, !isReadOnly);
        fileInfoRecord.put(URI, StringUtils.fromString(fullPath));
        return fileInfoRecord;
    }

    private static List<SmbService> matchingServices(String changedPath, List<SmbService> allServices) {
        List<SmbService> result = new ArrayList<>();
        for (SmbService registration : allServices) {
            if (normalizePath(changedPath).equals(normalizePath(registration.path()))) {
                result.add(registration);
            }
        }
        return result;
    }

    private static void notifyServicesForPath(Environment env, BObject listenerEndpoint, String changedPath,
                                              List<BMap<BString, Object>> addedFiles,
                                              List<SmbService> allServices,
                                              DiskShare diskShare,
                                              BMap<BString, Object> listenerConfig) {
        if (allServices == null || allServices.isEmpty()) {
            return;
        }
        List<SmbService> servicesToNotify = matchingServices(changedPath, allServices);
        if (servicesToNotify.isEmpty()) {
            return;
        }
        for (BMap<BString, Object> fileInfo : addedFiles) {
            String filePath = fileInfo.getStringValue(PATH).getValue();
            String extension = fileInfo.getStringValue(EXTENSION).getValue()
                    .toLowerCase();
            boolean isDirectory = fileInfo.getBooleanValue(IS_DIRECTORY);
            if (isDirectory) {
                continue;
            }
            for (SmbService registration : servicesToNotify) {
                try {
                    tryContentHandlers(env, listenerEndpoint, registration, filePath, extension, fileInfo, diskShare,
                            listenerConfig, changedPath);
                } catch (Exception exception) {
                    notifyServiceOnError(env, registration.service(), exception);
                }
            }
        }
    }

    private static void notifyServicesForDeletedFiles(Environment env, BObject listenerEndpoint, String changedPath,
                                                       List<String> deletedFiles,
                                                       List<SmbService> allServices,
                                                       BMap<BString, Object> listenerConfig) {
        if (allServices == null || allServices.isEmpty()) {
            return;
        }
        List<SmbService> servicesToNotify = matchingServices(changedPath, allServices);
        if (servicesToNotify.isEmpty()) {
            return;
        }
        for (SmbService registration : servicesToNotify) {
            HandlerMethodInfo handlerInfo = registration.handlers().get(ON_FILE_DELETE);
            if (handlerInfo == null) {
                continue;
            }
            for (String deletedFile : deletedFiles) {
                if (handlerInfo.matchesFileName(extractFileName(deletedFile))) {
                    invokeOnFileDeleteHandler(env, listenerEndpoint, registration, handlerInfo, deletedFile,
                            listenerConfig);
                }
            }
        }
    }

    private static String extractFileName(String filePath) {
        int lastSlash = filePath.lastIndexOf(SLASH_SUFFIX);
        return lastSlash >= 0 ? filePath.substring(lastSlash + 1) : filePath;
    }

    private static void invokeOnFileDeleteHandler(Environment env, BObject listenerEndpoint, SmbService registration,
                                                   HandlerMethodInfo handlerInfo, String deletedFile,
                                                   BMap<BString, Object> listenerConfig) {
        BObject service = registration.service();
        List<Object> args = new ArrayList<>();
        args.add(StringUtils.fromString(deletedFile));
        for (String paramRole : handlerInfo.extraParams()) {
            if (CALLER.equals(paramRole)) {
                BObject caller = getOrCreateCaller(listenerEndpoint, listenerConfig);
                if (caller != null) {
                    args.add(caller);
                }
            }
        }
        try {
            Object result = env.getRuntime().callMethod(service, ON_FILE_DELETE,
                    new StrandMetadata(handlerInfo.isolatedMethod(), null), args.toArray());
            if (result instanceof BError) {
                notifyServiceOnError(env, service, new Exception(((BError) result).getErrorMessage().getValue()));
            }
        } catch (Exception e) {
            notifyServiceOnError(env, service, e);
        }
    }

    private static void tryContentHandlers(Environment env, BObject listenerEndpoint, SmbService registration,
                                           String filePath, String extension, BMap<BString, Object> fileInfo,
                                           DiskShare diskShare, BMap<BString, Object> listenerConfig,
                                           String servicePath) {
        Map<String, HandlerMethodInfo> handlers = registration.handlers();
        String fileName = fileInfo.getStringValue(NAME).getValue();
        String handlerMethod = getHandlerMethodForExtension(extension);
        if (handlerMethod != null) {
            HandlerMethodInfo handlerInfo = handlers.get(handlerMethod);
            if (handlerInfo != null && handlerInfo.matchesFileName(fileName)) {
                invokeContentHandler(env, listenerEndpoint, registration, handlerInfo, handlerMethod, filePath,
                        fileInfo, diskShare, listenerConfig, servicePath);
                return;
            }
        }
        HandlerMethodInfo onFileInfo = handlers.get(ON_FILE);
        if (onFileInfo != null && onFileInfo.matchesFileName(fileName)) {
            invokeContentHandler(env, listenerEndpoint, registration, onFileInfo, ON_FILE, filePath, fileInfo,
                    diskShare, listenerConfig, servicePath);
        }
    }

    private static BMap<BString, Object> getFunctionConfigAnnotation(MethodType method) {
        return (BMap<BString, Object>) method.getAnnotation(
                StringUtils.fromString(ModuleUtils.getModule().toString() + COLON + FUNCTION_CONFIG));
    }

    private static PostProcessAction parsePostProcessAction(BMap<BString, Object> annotation, String field) {
        if (annotation == null) {
            return null;
        }
        Object actionObj = annotation.get(StringUtils.fromString(field));
        if (actionObj == null) {
            return null;
        }
        if (TypeUtils.getType(actionObj).getTag() == TypeTags.STRING_TAG) {
            return new PostProcessAction(true, null, false);
        }
        @SuppressWarnings("unchecked")
        BMap<BString, Object> moveRecord = (BMap<BString, Object>) actionObj;
        String moveTo = moveRecord.getStringValue(StringUtils.fromString(MOVE_TO)).getValue();
        boolean preserveSubDirs = moveRecord.getBooleanValue(StringUtils.fromString(PRESERVE_SUB_DIRS));
        return new PostProcessAction(false, moveTo, preserveSubDirs);
    }

    private static String getHandlerMethodForExtension(String extension) {
        return switch (extension) {
            case EXT_TXT, EXT_LOG, EXT_MD -> ON_FILE_TEXT;
            case EXT_JSON -> ON_FILE_JSON;
            case EXT_XML -> ON_FILE_XML;
            case EXT_CSV -> ON_FILE_CSV;
            default -> null;
        };
    }

    private static MethodType getMethod(ObjectType serviceType, String methodName) {
        for (MethodType method : serviceType.getMethods()) {
            if (method.getName().equals(methodName)) {
                return method;
            }
        }
        return null;
    }

    private static void invokeContentHandler(Environment env, BObject listenerEndpoint, SmbService registration,
                                             HandlerMethodInfo handlerInfo, String methodName,
                                             String filePath, BMap<BString, Object> fileInfo, DiskShare diskShare,
                                             BMap<BString, Object> listenerConfig, String servicePath) {
        BObject service = registration.service();
        Parameter[] parameters = handlerInfo.method().getParameters();
        if (parameters.length < 1) {
            return;
        }

        Type contentParamType = parameters[0].type;
        Object content;
        try {
            content = readFileContent(env, diskShare, filePath, methodName, contentParamType, listenerConfig);
        } catch (Exception e) {
            notifyServiceOnError(env, service, e);
            return;
        }

        if (content == null || content instanceof BError
                || TypeUtils.getType(content).getTag() == TypeTags.ERROR_TAG) {
            if (content instanceof BError bError) {
                notifyServiceOnError(env, service, new Exception(bError.getErrorMessage().getValue()));
            }
            return;
        }
        List<Object> args = new ArrayList<>();
        args.add(content);
        for (String paramRole : handlerInfo.extraParams()) {
            if (FILE_INFO.equals(paramRole)) {
                args.add(fileInfo);
            } else if (CALLER.equals(paramRole)) {
                BObject caller = getOrCreateCaller(listenerEndpoint, listenerConfig);
                if (caller != null) {
                    args.add(caller);
                }
            }
        }
        final Object[] methodArgs = args.toArray();
        final boolean isConcurrentSafe = handlerInfo.isolatedMethod();
        final PostProcessAction afterProcess = handlerInfo.afterProcess();
        final PostProcessAction afterError = handlerInfo.afterError();
        Thread.startVirtualThread(() -> {
            boolean isSuccess = false;
            Exception handlerError = null;
            try {
                Object result = env.getRuntime().callMethod(service, methodName,
                        new StrandMetadata(isConcurrentSafe, null), methodArgs);
                if (result instanceof BError bError) {
                    handlerError = new Exception(bError.getErrorMessage().getValue());
                } else {
                    isSuccess = true;
                }
            } catch (Exception e) {
                handlerError = e;
            }
            if (handlerError != null) {
                notifyServiceOnError(env, service, handlerError);
                if (afterError != null) {
                    executePostProcessAction(env, service, afterError, filePath, diskShare, servicePath);
                }
            }
            if (isSuccess && afterProcess != null) {
                executePostProcessAction(env, service, afterProcess, filePath, diskShare, servicePath);
            }
        });
    }

    private static void executePostProcessAction(Environment env, BObject service, PostProcessAction action,
                                                  String filePath, DiskShare diskShare, String servicePath) {
        String normalizedPath = filePath.startsWith(SLASH_SUFFIX) ? filePath.substring(1) : filePath;
        try {
            if (action.isDelete()) {
                diskShare.rm(normalizedPath);
            } else {
                executeMoveAction(diskShare, normalizedPath, filePath, action, servicePath);
            }
        } catch (Exception e) {
            notifyServiceOnError(env, service, e);
        }
    }

    private static void executeMoveAction(DiskShare diskShare, String normalizedPath, String filePath,
                                          PostProcessAction action, String servicePath) throws Exception {
        String destinationPath = calculateMoveDestination(filePath, servicePath, action);
        String normalizedDest = destinationPath.startsWith(SLASH_SUFFIX)
                ? destinationPath.substring(1) : destinationPath;
        ensureDirectoryExists(diskShare, normalizedDest);
        Set<AccessMask> accessMask = new HashSet<>();
        accessMask.add(AccessMask.DELETE);
        accessMask.add(AccessMask.GENERIC_WRITE);
        accessMask.add(AccessMask.GENERIC_READ);
        try (File file = diskShare.openFile(normalizedPath, accessMask, null,
                SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null)) {
            file.rename(normalizedDest, false);
        }
    }

    private static String calculateMoveDestination(String filePath, String servicePath, PostProcessAction action) {
        String moveTo = action.moveTo();
        String fileName = filePath.contains(SLASH_SUFFIX)
                ? filePath.substring(filePath.lastIndexOf(SLASH_SUFFIX) + 1)
                : filePath;
        if (!action.preserveSubDirs() || servicePath == null || servicePath.isEmpty()) {
            return ensureTrailingSlash(moveTo) + fileName;
        }
        String normalizedServicePath = ensureTrailingSlash(normalizePath(servicePath));
        String normalizedFilePath = filePath.startsWith(SLASH_SUFFIX) ? filePath : SLASH_SUFFIX + filePath;
        String relativePath = normalizedFilePath.startsWith(normalizedServicePath)
                ? normalizedFilePath.substring(normalizedServicePath.length())
                : "";
        return ensureTrailingSlash(moveTo) + (relativePath.isEmpty() ? fileName : relativePath);
    }

    private static String ensureTrailingSlash(String path) {
        if (path == null || path.isEmpty()) {
            return SLASH_SUFFIX;
        }
        return path.endsWith(SLASH_SUFFIX) ? path : path + SLASH_SUFFIX;
    }

    private static void ensureDirectoryExists(DiskShare diskShare, String fileDest) {
        String dirPath = fileDest.contains("/")
                ? fileDest.substring(0, fileDest.lastIndexOf('/'))
                : "";
        if (dirPath.isEmpty()) {
            return;
        }
        String[] parts = dirPath.split("/");
        StringBuilder current = new StringBuilder();
        for (String part : parts) {
            if (part.isEmpty()) {
                continue;
            }
            if (current.length() > 0) {
                current.append('/');
            }
            current.append(part);
            String dirToCreate = current.toString();
            try {
                if (!diskShare.folderExists(dirToCreate)) {
                    diskShare.mkdir(dirToCreate);
                }
            } catch (Exception e) {
                // Directory may have been created concurrently; ignore
            }
        }
    }

    private static Object readFileContent(Environment env, DiskShare diskShare, String filePath, String methodName,
                                           Type contentParamType, BMap<BString, Object> listenerConfig) {
        try {
            String normalizedPath = filePath.startsWith(SLASH_SUFFIX) ? filePath.substring(1) : filePath;
            Set<AccessMask> accessMask = new HashSet<>();
            accessMask.add(AccessMask.GENERIC_READ);

            Type referredType = TypeUtils.getReferredType(contentParamType);
            boolean isStreamType = referredType.getTag() == TypeTags.STREAM_TAG;

            if (isStreamType) {
                File file = diskShare.openFile(normalizedPath, accessMask, null,
                        SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null);
                InputStream inputStream = file.getInputStream();
                return switch (methodName) {
                    case ON_FILE_CSV -> parseCsvContentAsStream(inputStream, contentParamType);
                    case ON_FILE -> parseByteContentAsStream(inputStream);
                    default -> {
                        inputStream.close();
                        file.close();
                        yield readFileContentAsBytes(env, diskShare, normalizedPath, methodName, contentParamType,
                                listenerConfig, filePath);
                    }
                };
            }
            return readFileContentAsBytes(env, diskShare, normalizedPath, methodName, contentParamType,
                    listenerConfig, filePath);
        } catch (Exception e) {
            return SmbUtil.createError(FILE_READ_ERROR + e.getMessage(), SMB_ERROR);
        }
    }

    private static Object readFileContentAsBytes(Environment env, DiskShare diskShare, String normalizedPath,
                                                  String methodName, Type contentParamType,
                                                  BMap<BString, Object> listenerConfig, String filePath)
            throws Exception {
        Set<AccessMask> accessMask = new HashSet<>();
        accessMask.add(AccessMask.GENERIC_READ);
        try (File file = diskShare.openFile(normalizedPath, accessMask, null,
                SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null);
             InputStream inputStream = file.getInputStream()) {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            byte[] buffer = new byte[ARRAY_SIZE];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
            byte[] bytes = outputStream.toByteArray();

            boolean laxDataBinding = listenerConfig != null &&
                    listenerConfig.getBooleanValue(StringUtils.fromString(ENDPOINT_CONFIG_LAX_DATA_BINDING));
            return switch (methodName) {
                case ON_FILE_TEXT -> StringUtils.fromString(new String(bytes, StandardCharsets.UTF_8));
                case ON_FILE_JSON -> parseJsonContent(bytes, contentParamType, laxDataBinding);
                case ON_FILE_XML -> parseXmlContent(bytes, contentParamType, laxDataBinding);
                case ON_FILE_CSV -> parseCsvContent(env, bytes, contentParamType, listenerConfig, filePath);
                case ON_FILE -> parseByteContent(bytes);
                default -> ValueCreator.createArrayValue(bytes);
            };
        }
    }

    private static Object parseJsonContent(byte[] bytes, Type targetType, boolean laxDataBinding) {
        Type referredType = TypeUtils.getReferredType(targetType);
        if (referredType.getTag() == TypeTags.JSON_TAG || referredType.getTag() == TypeTags.MAP_TAG) {
            try {
                return JsonUtils.parse(new String(bytes, StandardCharsets.UTF_8));
            } catch (Exception e) {
                return SmbUtil.createError(JSON_PARSE_ERROR + e.getMessage(), SMB_ERROR);
            }
        }
        return SmbContentConverter.convertBytesToJson(bytes, referredType, laxDataBinding);
    }

    private static Object parseXmlContent(byte[] bytes, Type targetType, boolean laxDataBinding) {
        return SmbContentConverter.convertBytesToXml(bytes, TypeUtils.getReferredType(targetType), laxDataBinding);
    }

    private static Object parseCsvContent(Environment env, byte[] bytes, Type targetType,
                                           BMap<BString, Object> listenerConfig, String filePath) {
        try {
            Type referredType = TypeUtils.getReferredType(targetType);
            boolean laxDataBinding = listenerConfig != null &&
                    listenerConfig.getBooleanValue(StringUtils.fromString(ENDPOINT_CONFIG_LAX_DATA_BINDING));
            BMap<?, ?> csvFailSafe = listenerConfig != null ?
                    listenerConfig.getMapValue(StringUtils.fromString(ENDPOINT_CONFIG_CSV_FAIL_SAFE)) : null;

            if (referredType.getTag() == TypeTags.ARRAY_TAG) {
                ArrayType arrayType = (ArrayType) referredType;
                Type elementType = TypeUtils.getReferredType(arrayType.getElementType());
                if (elementType.getTag() == TypeTags.ARRAY_TAG) {
                    ArrayType innerArrayType = (ArrayType) elementType;
                    if (innerArrayType.getElementType().getTag() == TypeTags.STRING_TAG) {
                        return parseStringArrayArray(bytes);
                    }
                }
                String fileNamePrefix = SmbContentConverter.deriveFileNamePrefix(filePath);
                return SmbContentConverter.convertBytesToCsv(env, bytes, targetType,
                        laxDataBinding, csvFailSafe, fileNamePrefix);
            }
            return parseStringArrayArray(bytes);
        } catch (Exception e) {
            return SmbUtil.createError(CSV_PARSE_ERROR + e.getMessage(), SMB_ERROR);
        }
    }

    private static Object parseStringArrayArray(byte[] bytes) {
        String csvContent = new String(bytes, StandardCharsets.UTF_8);
        List<BArray> rows = new ArrayList<>();
        String[] lines = csvContent.split("\\r?\\n");
        for (String line : lines) {
            if (line.trim().isEmpty()) {
                continue;
            }
            List<BString> fields = new ArrayList<>();
            StringBuilder currentField = new StringBuilder();
            boolean inQuotes = false;

            for (int index = 0; index < line.length(); index++) {
                char current = line.charAt(index);
                if (current == '"') {
                    if (inQuotes && index + 1 < line.length() && line.charAt(index + 1) == '"') {
                        currentField.append('"');
                        index++;
                    } else {
                        inQuotes = !inQuotes;
                    }
                } else if (current == ',' && !inQuotes) {
                    fields.add(StringUtils.fromString(currentField.toString()));
                    currentField = new StringBuilder();
                } else {
                    currentField.append(current);
                }
            }
            fields.add(StringUtils.fromString(currentField.toString()));
            BArray row = ValueCreator.createArrayValue(fields.toArray(new BString[0]));
            rows.add(row);
        }

        ArrayType stringArrayType = TypeCreator.createArrayType(PredefinedTypes.TYPE_STRING);
        ArrayType arrayOfStringArraysType = TypeCreator.createArrayType(stringArrayType);
        return ValueCreator.createArrayValue(rows.toArray(new BArray[0]), arrayOfStringArraysType);
    }

    private static Object parseByteContent(byte[] bytes) {
        return ValueCreator.createArrayValue(bytes);
    }

    private static Object parseByteContentAsStream(InputStream inputStream) {
        return ByteIterator.createByteStream(inputStream);
    }

    private static Object parseCsvContentAsStream(InputStream inputStream, Type targetType) {
        Type referredType = TypeUtils.getReferredType(targetType);
        StreamType streamType = (StreamType) referredType;
        Type constraintType = streamType.getConstrainedType();
        Type referredConstraintType = TypeUtils.getReferredType(constraintType);
        if (referredConstraintType.getTag() == TypeTags.ARRAY_TAG) {
            ArrayType arrayType = (ArrayType) referredConstraintType;
            if (arrayType.getElementType().getTag() == TypeTags.STRING_TAG) {
                return CsvIterator.createStringArrayStream(inputStream, constraintType, false);
            }
        }
        return CsvIterator.createRecordStream(inputStream, constraintType, false);
    }

    private static void notifyServiceOnError(Environment env, BObject service, Exception e) {
        try {
            BError bError = ErrorCreator.createError(
                    ModuleUtils.getModule(),
                    SMB_ERROR,
                    StringUtils.fromString(e.getMessage()),
                    null,
                    null);
            Object result = env.getRuntime().callMethod(service, ON_ERROR_METHOD,
                    new StrandMetadata(true, null), bError);
            if (result instanceof BError) {
                log.debug("onError returned an error: {}", ((BError) result).getErrorMessage().getValue());
            }
        } catch (Exception ignored) {
            log.debug("Service does not implement onError or error invoking onError: {}", ignored.getMessage());
        }
    }

    private static void notifyServicesOnError(Environment env, List<SmbService> services, Exception e) {
        if (services == null || services.isEmpty()) {
            return;
        }
        BError bError = ErrorCreator.createError(ModuleUtils.getModule(), SMB_ERROR,
                StringUtils.fromString(e.getMessage()), null, null);
        for (SmbService registration : services) {
            try {
                Object result = env.getRuntime().callMethod(registration.service(), ON_ERROR_METHOD, null, bError);
                if (result instanceof BError) {
                    log.debug("onError returned an error: {}", ((BError) result).getErrorMessage().getValue());
                }
            } catch (Exception ignored) {
                log.debug("Service does not implement onError or error invoking onError: {}", ignored.getMessage());
            }
        }
    }

    private static AuthenticationContext createKerberosAuthContext(BMap<?, ?> kerberosConfig,
                                                                    String password, String domain) {
        try {
            String principal = kerberosConfig.getStringValue(StringUtils.fromString(KERBEROS_PRINCIPAL)).getValue();
            BString keytabBStr = kerberosConfig.getStringValue(StringUtils.fromString(KERBEROS_KEYTAB));
            BString configFileBStr = kerberosConfig.getStringValue(StringUtils.fromString(KERBEROS_CONFIG_FILE));
            String keytabPath = keytabBStr != null ? keytabBStr.getValue() : null;
            String configFile = configFileBStr != null ? configFileBStr.getValue() : null;

            String realm = principal.substring(principal.indexOf('@') + 1);
            String kerberosUsername = principal.substring(0, principal.indexOf('@'));

            setKerberosSystemProperties(configFile);

            Subject subject = (keytabPath != null && !keytabPath.isEmpty())
                    ? loginWithKeytab(principal, keytabPath)
                    : (password != null && !password.isEmpty())
                    ? loginWithPassword(principal, password)
                    : loginWithTicketCache(principal);

            return new GSSAuthenticationContext(kerberosUsername, realm, subject, null);
        } catch (Exception e) {
            throw new RuntimeException(KERBEROS_AUTH_CONTEXT_ERROR + e.getMessage(), e);
        }
    }

    private static void setKerberosSystemProperties(String configFile) {
        if (configFile != null && !configFile.isEmpty()) {
            System.setProperty("java.security.krb5.conf", configFile);
        }
        System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");
    }

    private static Subject loginWithKeytab(String principal, String keytabPath) throws LoginException {
        Configuration jaasConfig = new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                Map<String, String> options = new HashMap<>();
                options.put("useKeyTab", "true");
                options.put("keyTab", keytabPath);
                options.put("storeKey", "true");
                options.put("doNotPrompt", "true");
                options.put("principal", principal);

                return new AppConfigurationEntry[]{
                        new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",
                                AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options
                        )
                };
            }
        };
        LoginContext loginContext = new LoginContext("SmbKerberosListener", null, null, jaasConfig);
        loginContext.login();
        return loginContext.getSubject();
    }

    private static Subject loginWithPassword(String principal, String password) throws LoginException {
        Configuration jaasConfig = new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                Map<String, String> options = new HashMap<>();
                options.put("useTicketCache", "false");
                options.put("renewTGT", "false");
                options.put("doNotPrompt", "false");
                options.put("storeKey", "true");

                return new AppConfigurationEntry[]{
                        new AppConfigurationEntry(
                                "com.sun.security.auth.module.Krb5LoginModule",
                                AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                                options
                        )
                };
            }
        };

        CallbackHandler callbackHandler = callbacks -> {
            for (Callback callback : callbacks) {
                if (callback instanceof NameCallback) {
                    ((NameCallback) callback).setName(principal);
                } else if (callback instanceof PasswordCallback) {
                    ((PasswordCallback) callback).setPassword(password.toCharArray());
                }
            }
        };

        LoginContext loginContext = new LoginContext("SmbKerberosListener", null, callbackHandler, jaasConfig);
        loginContext.login();
        return loginContext.getSubject();
    }

    private static Subject loginWithTicketCache(String principal) throws LoginException {
        Configuration jaasConfig = new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                Map<String, String> options = new HashMap<>();
                options.put("useTicketCache", "true");
                options.put("renewTGT", "true");
                options.put("doNotPrompt", "true");
                options.put("storeKey", "false");
                options.put("principal", principal);

                return new AppConfigurationEntry[]{
                        new AppConfigurationEntry(
                                "com.sun.security.auth.module.Krb5LoginModule",
                                AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                                options
                        )
                };
            }
        };

        LoginContext loginContext = new LoginContext("SmbKerberosListener", null, null, jaasConfig);
        loginContext.login();
        return loginContext.getSubject();
    }

    private static BArray createUtcTuple(long epochMillis) {
        long seconds = epochMillis / 1000;
        long remainingMillis = epochMillis % 1000;
        BigDecimal fraction = new BigDecimal(remainingMillis).movePointLeft(3);
        TupleType utcTupleType = TypeCreator.createTupleType(
                List.of(PredefinedTypes.TYPE_INT, PredefinedTypes.TYPE_DECIMAL));
        BArray timeData = ValueCreator.createTupleValue(utcTupleType);
        timeData.add(0, seconds);
        timeData.add(1, ValueCreator.createDecimalValue(fraction));
        return timeData;
    }
}

