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

    public final static String AUTHORIZATION_ENDPOINT = "https://login.microsoftonline.com";
    public final static String AUTHORIZATION_HEADER = "Authorization";
    public final static String ARM_ENDPOINT = "https://management.azure.com";

    public final static String NETWORK_SECURITY_GROUPS_RESOURCE = "/subscriptions/%s/resourceGroups/%s/providers/"
            + "Microsoft.Network/networkSecurityGroups/%s?api-version=2016-03-30";
    public final static String NETWORK_INTERFACES_RESOURCE = "/subscriptions/%s/resourceGroups/%s/providers/"
            + "Microsoft.Network/networkInterfaces/%s?api-version=2016-03-30";
    public final static String TAGS_RESOURCE = "/subscriptions/%s/resources?$filter=tagname+eq+'%s'&api-version=2015-01-01";
    public final static String VIRTUAL_MACHINE_SCALE_SET_VIRTUAL_MACHINES_RESOURCE =
            "/subscriptions/%s/resourceGroups/%s/providers/Microsoft"
                    + ".Compute/virtualMachineScaleSets/%s/virtualMachines?api-version=2016-03-30";
    public final static String VIRTUAL_MACHINE_SCALE_SET_NETWORK_INTERFACES_RESOURCE =
            "/subscriptions/%s/resourceGroups/%s/providers/Microsoft"
                    + ".Compute/virtualMachineScaleSets/%s/virtualMachines/%s/networkInterfaces/%s?api-version=2016-03-30";

    public final static String AZURE_USERNAME = "AZURE_USERNAME";
    public final static String AZURE_CREDENTIAL = "AZURE_CREDENTIAL";
    public final static String AZURE_TENANT_ID = "AZURE_TENANT_ID";
    public final static String AZURE_CLIENT_ID = "AZURE_CLIENT_ID";
    public final static String AZURE_SUBSCRIPTION_ID = "AZURE_SUBSCRIPTION_ID";
    public final static String AZURE_RESOURCE_GROUP = "AZURE_RESOURCE_GROUP";
    public final static String AZURE_NETWORK_SECURITY_GROUP = "AZURE_NETWORK_SECURITY_GROUP";
    public final static String AZURE_NETWORK_INTERFACE_TAG = "AZURE_NETWORK_INTERFACE_TAG";
    public final static String AZURE_VIRTUAL_MACHINE_SCALE_SET = "AZURE_VIRTUAL_MACHINE_SCALE_SET";
    public final static String AZURE_VALIDATE_AUTHORITY = "AZURE_VALIDATE_AUTHORITY";

}
