/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <sys/param.h>

#include <s2n.h>
#include <time.h>

#include "error/s2n_errno.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_alerts.h"
#include "tls/s2n_tls.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"

int s2n_server_nst_recv(struct s2n_connection *conn)
{
    /* Look at lifetime hint and store session ticket */
    return 0;
}

int s2n_server_nst_send(struct s2n_connection *conn)
{
    /*Construct session ticket
     * -serialize state
     * -encrypt state
     * -include key name
     * -generate iv and mac
     *
     *Add lifetime hint
     */
    return 0;
}
