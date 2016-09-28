/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.clustering.azure;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hazelcast.config.Config;
import com.hazelcast.config.NetworkConfig;
import com.hazelcast.config.TcpIpConfig;
import com.hazelcast.core.*;
import com.microsoft.aad.adal4j.AuthenticationResult;
import org.apache.axis2.clustering.ClusteringFault;
import org.apache.axis2.clustering.ClusteringMessage;
import org.apache.axis2.description.Parameter;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.params.HttpConnectionParams;
import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.carbon.clustering.azure.authentication.Authentication;
import org.wso2.carbon.clustering.azure.domain.NetworkInterface;
import org.wso2.carbon.clustering.azure.domain.NetworkSecurityGroup;
import org.wso2.carbon.clustering.azure.exceptions.AzureMembershipSchemeException;
import org.wso2.carbon.core.clustering.hazelcast.HazelcastCarbonClusterImpl;
import org.wso2.carbon.core.clustering.hazelcast.HazelcastMembershipScheme;
import org.wso2.carbon.core.clustering.hazelcast.HazelcastUtil;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 *
 * Azure membership scheme provides carbon cluster discovery on Microsoft Azure
 */
public class AzureMembershipScheme implements HazelcastMembershipScheme {

    private static final Log log = LogFactory.getLog(AzureMembershipScheme.class);
    private final Map<String, Parameter> parameters;
    protected final NetworkConfig nwConfig;
    private final List<ClusteringMessage> messageBuffer;
    private HazelcastInstance primaryHazelcastInstance;
    private HazelcastCarbonClusterImpl carbonCluster;
    // private boolean validationAuthority;

    public AzureMembershipScheme(Map<String, Parameter> parameters,
            String primaryDomain,
            Config config,
            HazelcastInstance primaryHazelcastInstance,
            List<ClusteringMessage> messageBuffer) {
        this.parameters = parameters;
        this.primaryHazelcastInstance = primaryHazelcastInstance;
        this.messageBuffer = messageBuffer;
        this.nwConfig = config.getNetworkConfig();
    }

    @Override
    public void setPrimaryHazelcastInstance(HazelcastInstance primaryHazelcastInstance) {
        this.primaryHazelcastInstance = primaryHazelcastInstance;
    }

    @Override
    public void setLocalMember(Member localMember) {
    }

    @Override
    public void setCarbonCluster(HazelcastCarbonClusterImpl hazelcastCarbonCluster) {
        this.carbonCluster = hazelcastCarbonCluster;
    }

    @Override
    public void init() throws ClusteringFault {
        try {
            log.info("Initializing Azure membership scheme...");
            nwConfig.getJoin().getMulticastConfig().setEnabled(false);
            nwConfig.getJoin().getAwsConfig().setEnabled(false);
            TcpIpConfig tcpIpConfig = nwConfig.getJoin().getTcpIpConfig();
            tcpIpConfig.setEnabled(true);

            String username = getConstant(AzureConstants.AZURE_USERNAME, "", true);
            String credential = getConstant(AzureConstants.CREDENTIAL, "", false);
            String tenantId = getConstant(AzureConstants.TENANT_ID, "", false);
            String clientId = getConstant(AzureConstants.CLIENT_ID, "", false);
            String subscriptionId = getConstant(AzureConstants.SUBSCRIPTION_ID, "", false);
            String resourceGroup = getConstant(AzureConstants.RESOURCE_GROUP, "", false);
            String networkSecurityGroup = getConstant(AzureConstants.NETWORK_SECURITY_GROUP, "default", false);
            String networkInterfaceTag = getConstant(AzureConstants.NETWORK_INTERFACE_TAG, "default", false);
            boolean validationAuthority = Boolean.parseBoolean(getConstant(AzureConstants.VALIDATION_AUTHORITY, "false", true));

            if (networkInterfaceTag==null && networkSecurityGroup==null) {
                throw new ClusteringFault(String.format("both %s and %s parameters are empty. define at least one of them",
                        AzureConstants.NETWORK_SECURITY_GROUP, AzureConstants.NETWORK_INTERFACE_TAG));
            }

            Authentication auth = new Authentication();
            AuthenticationResult authResult = auth.getAuthToken(username, credential, tenantId, clientId,
                    validationAuthority);

            log.info(String.format("Azure clustering configuration: [autherization-endpont] %s , [arm-endpont] %s , " +
                    "[tenant-id] %s , [client-id] %s",
                    AzureConstants.AUTHORIZATION_ENDPOINT, AzureConstants.ARM_ENDPOINT, tenantId, clientId));

            List<String> ipAddresses = findIPAddresses(authResult.getAccessToken(), subscriptionId, resourceGroup,
                    networkSecurityGroup, networkInterfaceTag);
            for (Object IPAddress : ipAddresses) {
                nwConfig.getJoin().getTcpIpConfig().addMember(IPAddress.toString());
                log.info(String.format("Member added to cluster configuration: [IP Address] %s", IPAddress.toString()));
            }
            log.info("Azure membership scheme initialized successfully");
        } catch (Exception ex) {
            throw new ClusteringFault("Azure membership initialization failed", ex);
        }
    }

    protected List<String> findIPAddresses(String accessToken, String subscriptionID, String resourceGroup,
                                           String networkSecurityGroup, String networkInterfaceTag)
            throws AzureMembershipSchemeException {

        InputStream inputStream;
        List<String> ipAddresses = new ArrayList<>();
        ObjectMapper objectMapper = new ObjectMapper();

        if (networkInterfaceTag == null) {
            // list NICs grouped in the specified network security group
            String url = AzureConstants.ARM_ENDPOINT + String.format(AzureConstants.NETWORK_SECURITY_GROUPS_RESOURCE,
                    subscriptionID, resourceGroup, networkSecurityGroup);
            inputStream = invokeGetMethod(url, accessToken);

            try {
                NetworkSecurityGroup nsg = objectMapper.readValue(inputStream, NetworkSecurityGroup.class);
                List ninames = nsg.getProperties().getNetworkInterfaceNames();

                for (Object niname : ninames) {
                    url = AzureConstants.ARM_ENDPOINT + String.format(AzureConstants.NETWORK_INTERFACES_RESOURCE,
                            subscriptionID, resourceGroup, niname);
                    inputStream = invokeGetMethod(url, accessToken);
                    NetworkInterface ni = objectMapper.readValue(inputStream, NetworkInterface.class);
                    ipAddresses.add(ni.getProperties().getIPAddress());
                }
            } catch (IOException ex) {
                throw new AzureMembershipSchemeException("Could not find VM IP addresses", ex);
            }
        } else if (networkSecurityGroup == null) { //List NICs according to the tags
            try {
                String url = AzureConstants.ARM_ENDPOINT + String.format(AzureConstants.TAGS_RESOURCE,
                        subscriptionID, networkInterfaceTag);
                JSONObject rootElement = new JSONObject(inputStreamToString(invokeGetMethod(url, accessToken)));
                JSONArray values = rootElement.getJSONArray("value");
                List<String> ninames = new ArrayList<>();
                for (int i = 0; i < values.length(); i++) {
                    JSONObject firstelement = values.getJSONObject(i);
                    Object name = firstelement.get("name");
                    if((name != null) && StringUtils.isNotEmpty(name.toString())) {
                        ninames.add(name.toString());
                    }
                }
                for (Object niname : ninames) {
                    url = AzureConstants.ARM_ENDPOINT + String.format(AzureConstants.NETWORK_INTERFACES_RESOURCE,
                            subscriptionID, resourceGroup, niname);
                    inputStream = invokeGetMethod(url, accessToken);
                    NetworkInterface ni = objectMapper.readValue(inputStream, NetworkInterface.class);
                    ipAddresses.add(ni.getProperties().getIPAddress());
                }
            } catch (IOException ex) {
                throw new AzureMembershipSchemeException("Could not find VM IP addresses", ex);
            }
        } else {
            throw new AzureMembershipSchemeException("EITHER networkSecurityGroup OR networkInterfaceTag "
                    + "must be chosen as the grouping method; not both of them");
        }
        return ipAddresses;
    }

    public InputStream invokeGetMethod(String url, String accessToken) throws AzureMembershipSchemeException {

        InputStream inputStream;
        try {
            final HttpClient httpClient = new DefaultHttpClient();
            HttpConnectionParams.setConnectionTimeout(httpClient.getParams(), 10000);
            HttpGet httpGet = new HttpGet(url);
            httpGet.addHeader("Authorization", "Bearer " + accessToken);
            HttpResponse response = httpClient.execute(httpGet);
            HttpEntity entity = response.getEntity();
            inputStream = entity.getContent();
        } catch (Exception ex) {
            throw new AzureMembershipSchemeException("Could not connect to Azure API", ex);
        }
        return inputStream;
    }

    public void joinGroup() throws ClusteringFault {
        primaryHazelcastInstance.getCluster().addMembershipListener(new AzureMembershipSchemeListener());
    }

    private Parameter getParameter(String name) {
        return parameters.get(name);
    }

    protected String getConstant(String constant, String defaultValue, boolean isOptional) throws ClusteringFault {
        String param = System.getenv(constant);
        Parameter parameter;
        if (StringUtils.isEmpty(param)) {
            parameter = getParameter(constant);
            if (parameter == null) {
                param = defaultValue;
                if (StringUtils.isEmpty(param) && !isOptional) {   //should leave defaultvalue blank if the value is mandatory
                    throw new ClusteringFault(String.format("Azure %s parameter not found", constant));
                } else {
                    param = null;
                }
            } else {
                return parameter.getValue().toString();
            }
        }
        return param;
    }

    public String inputStreamToString(InputStream instream) throws IOException {
        StringBuilder sb = new StringBuilder();
        BufferedReader r = new BufferedReader(new InputStreamReader(instream), 1000);
        for (String line = r.readLine(); line != null; line = r.readLine()) {
            sb.append(line);
        }
        instream.close();
        return sb.toString();
    }

    private class AzureMembershipSchemeListener implements MembershipListener {

        @Override
        public void memberAdded(MembershipEvent membershipEvent) {
            Member member = membershipEvent.getMember();
            // Send all cluster messages
            carbonCluster.memberAdded(member);
            log.info(String.format("Member joined [%s] : %s", member.getUuid(), member.getSocketAddress().toString()));
            // Wait for sometime for the member to completely join before replaying messages
            try {
                Thread.sleep(5000);
            } catch (InterruptedException ignored) {
            }
            HazelcastUtil.sendMessagesToMember(messageBuffer, member, carbonCluster);
        }

        @Override
        public void memberRemoved(MembershipEvent membershipEvent) {
            Member member = membershipEvent.getMember();
            carbonCluster.memberRemoved(member);
            log.info(String.format("Member left [%s] : %s", member.getUuid(), member.getSocketAddress().toString()));
        }

        @Override
        public void memberAttributeChanged(MemberAttributeEvent memberAttributeEvent) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Member attribute changed [%s] %s", memberAttributeEvent.getKey(), memberAttributeEvent.getValue()));
            }
        }
    }
}
