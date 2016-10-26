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
package org.wso2.carbon.clustering.azure.domain;

import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

/**
 * Azure NetworkSecurityGroup NetworkSecurityGroupProperties
 */
public class NetworkSecurityGroupProperties {

    private List networkInterfaces = new ArrayList();

    public List getNetworkInterfaces() {
        return networkInterfaces;
    }

    public void setNetworkInterfaces(List networkInterfaces) {
        this.networkInterfaces = networkInterfaces;
    }

    public List getNetworkInterfaceNames() {
        StringTokenizer[] st = new StringTokenizer[networkInterfaces.size()];
        String nicName = "";
        List<String> nicNames = new ArrayList<>();
        for (int i = 0; i < networkInterfaces.size(); i++) {
            st[i] = new StringTokenizer(networkInterfaces.get(i).toString(), "/");
            while (st[i].hasMoreTokens()) {
                nicName = st[i].nextToken();
            }
            nicName = nicName.substring(0, nicName.length() - 1);
            nicNames.add(nicName);
        }
        return nicNames;
    }
}
