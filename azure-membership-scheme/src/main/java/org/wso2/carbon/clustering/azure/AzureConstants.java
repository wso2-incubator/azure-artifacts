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

/**
 * AzureConstants for Azure membership scheme
 */
public class AzureConstants {

    public final static String DEFAULT_AUTHORIZATION_ENDPOINT = "https://login.microsoftonline.com";
    public final static String DEFAULT_ARM_ENDPOINT = "https://management.azure.com";
    public final static String AUTHORIZATION_HEADER = "Authorization";
    public final static String API_VERSION_QUERY_PARAM = "api-version=";

    public final static String NETWORK_SECURITY_GROUPS_RESOURCE =
            "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/networkSecurityGroups/%s";
    public final static String NETWORK_INTERFACES_RESOURCE = "/subscriptions/%s/resourceGroups/%s/providers/Microsoft"
            + ".Network/networkInterfaces/%s";
    public final static String VIRTUAL_MACHINE_SCALE_SET_VIRTUAL_MACHINES_RESOURCE =
            "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachineScaleSets/%s/virtualMachines";
    public final static String VIRTUAL_MACHINE_SCALE_SET_NETWORK_INTERFACES_RESOURCE =
            "/subscriptions/%s/resourceGroups/%s/providers/Microsoft"
                    + ".Compute/virtualMachineScaleSets/%s/virtualMachines/%s/networkInterfaces/%s";
    public final static String DEFAULT_AZURE_API_VERSION = "2016-03-30";

    public final static String AZURE_API_VERSION = "AZURE_API_VERSION";
    public final static String AUTHORIZATION_ENDPOINT = "AUTHORIZATION_ENDPOINT";
    public final static String ARM_ENDPOINT = "ARM_ENDPOINT";
    public final static String AZURE_USERNAME = "AZURE_USERNAME";
    public final static String AZURE_CREDENTIAL = "AZURE_CREDENTIAL";
    public final static String AZURE_TENANT_ID = "AZURE_TENANT_ID";
    public final static String AZURE_CLIENT_ID = "AZURE_CLIENT_ID";
    public final static String AZURE_SUBSCRIPTION_ID = "AZURE_SUBSCRIPTION_ID";
    public final static String AZURE_RESOURCE_GROUP = "AZURE_RESOURCE_GROUP";
    public final static String AZURE_NETWORK_SECURITY_GROUP = "AZURE_NETWORK_SECURITY_GROUP";
    public final static String AZURE_NETWORK_INTERFACE_TAG_KEY = "AZURE_NETWORK_INTERFACE_TAG_KEY";
    public final static String AZURE_NETWORK_INTERFACE_TAG_VALUE = "AZURE_NETWORK_INTERFACE_TAG_VALUE";
    public final static String AZURE_VIRTUAL_MACHINE_SCALE_SETS = "AZURE_VIRTUAL_MACHINE_SCALE_SETS";
    public final static String AZURE_VALIDATE_AUTHORITY = "AZURE_VALIDATE_AUTHORITY";

}
