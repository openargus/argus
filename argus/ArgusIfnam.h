#ifndef __ARGUS_IFNAM_H
# define __ARGUS_IFNAM_H

# ifdef HAVE_CONFIG_H
#  include "argus_config.h"
# endif

# include "argus_compat.h"
# include "ArgusModeler.h"
# include "ArgusSource.h"

int
shortname_ethdev_unique(char *in, char *out, size_t outlen,
                        struct ArgusListStruct *ArgusDeviceList);

#else
extern int shortname_ethdev_unique(char *, char *, size_t, struct ArgusListStruct *);
#endif
