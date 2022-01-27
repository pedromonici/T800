#include "stateless.h"

#include "lwip/tcp.h"
#include "lwip/priv/tcp_priv.h"
#include "esp_log.h"

static const char *TAG = "Firewall Stateless";

err_t decision_tree_depth_6(struct pbuf *p) {
    const struct ip_hdr *iphdr = (struct ip_hdr *)p->payload;

    if (IPH_PROTO(iphdr) != IP_PROTO_TCP) {
        /* ESP_LOGI(TAG, "IS_NOT_A_TCP_PACKET"); */
        return ERR_OK;
    }
    /* ESP_LOGI(TAG, "IS_A_TCP_PACKET"); */

    u16_t iphdr_hlen = IPH_HL_BYTES(iphdr);

    /* increase payload pointer (guarded by length check above) */
    struct tcp_hdr *tcphdr = (struct tcp_hdr *) ((u8_t *)p->payload + iphdr_hlen);

    if (htons(IPH_LEN(iphdr)) < 64.5) {
        if (TCPH_HDRLEN(tcphdr) < 38.0) {
            if ((IPH_OFFSET(iphdr) & IP_DF) < 0.5) {
                if ((TCPH_FLAGS(tcphdr) & TCP_SYN) < 0.5) {
                    if (htons(IPH_LEN(iphdr)) < 40.5) {
                        if (htons(tcphdr->wnd) < 506.5) {
                            return ERR_ABRT;
                        } else {
                            return ERR_OK;
                        }
                    } else {
                        if ((htons(IPH_LEN(iphdr)) - htons(IPH_HL(iphdr))) < 0.5) {
                            return ERR_ABRT;
                        } else {
                            return ERR_ABRT;
                        }
                    }
                } else {
                    if (htons(tcphdr->wnd) < 65524.0) {
                        if (TCPH_HDRLEN(tcphdr) < 22.0) {
                            return ERR_ABRT;
                        } else {
                            return ERR_OK;
                        }
                    } else {
                        if (htons(IPH_TOS(iphdr) >> 2) < 4.0) {
                            return ERR_OK;
                        } else {
                            return ERR_ABRT;
                        }
                    }
                }
            } else {
                return ERR_ABRT;
            }
        } else {
            if (htons(tcphdr->wnd) < 15749.0) {
                return ERR_ABRT;
            } else {
                if (htons(tcphdr->wnd) < 64520.0) {
                    if (htons(IPH_ID(iphdr)) < 5.5) {
                        return ERR_ABRT;
                    } else {
                        if (htons(tcphdr->wnd) < 16472.0) {
                            return ERR_OK;
                        } else {
                            return ERR_OK;
                        }
                    }
                } else {
                    if ((TCPH_FLAGS(tcphdr) & TCP_CWR) < 0.5) {
                        return ERR_ABRT;
                    } else {
                        return ERR_ABRT;
                    }
                }
            }
        }
    } else {
        if ((TCPH_FLAGS(tcphdr) & TCP_ACK) < 0.5) {
            return ERR_ABRT;
        } else {
            return ERR_ABRT;
        }
    }

    return ERR_OK;
}

err_t decision_tree_depth_7(struct pbuf *p) {
    const struct ip_hdr *iphdr = (struct ip_hdr *)p->payload;

    if (IPH_PROTO(iphdr) != IP_PROTO_TCP) {
        ESP_LOGI(TAG, "IS_NOT_A_TCP_PACKET");
        return ERR_OK;
    }

    ESP_LOGI(TAG, "IS_A_TCP_PACKET");

    u16_t iphdr_hlen = IPH_HL_BYTES(iphdr);
    /* increase payload pointer (guarded by length check above) */
    struct tcp_hdr *tcphdr = (struct tcp_hdr *) ((u8_t *)p->payload + iphdr_hlen);

    if (htons(IPH_LEN(iphdr)) < 64.5) {
        if (TCPH_HDRLEN(tcphdr) < 38.0) {
            if ((IPH_OFFSET(iphdr) & IP_DF) < 0.5) {
                if ((TCPH_FLAGS(tcphdr) & TCP_SYN) < 0.5) {
                    if (htons(IPH_LEN(iphdr)) < 40.5) {
                        if (htons(tcphdr->wnd) < 506.5) {
                            return ERR_ABRT;
                        } else {
                            if (htons(tcphdr->wnd) < 1300.0) {
                                return ERR_OK;
                            } else {
                                return ERR_ABRT;
                            }
                        }
                    } else {
                        if (htons(IPH_ID(iphdr)) < 6.0) {
                            return ERR_ABRT;
                        } else {
                            return ERR_ABRT;
                        }
                    }
                } else {
                    if (htons(tcphdr->wnd) < 65524.0) {
                        if (htons(IPH_LEN(iphdr)) < 42.0) {
                            if (htons(tcphdr->wnd) < 520.5) {
                                return ERR_OK;
                            } else {
                                return ERR_ABRT;
                            }
                        } else {
                            if (htons(tcphdr->wnd) < 1026.0) {
                                return ERR_OK;
                            } else {
                                return ERR_ABRT;
                            }
                        }
                    } else {
                        if (htons(IPH_TOS(iphdr) >> 2) < 4.0) {
                            if (htons(IPH_LEN(iphdr)) < 42.0) {
                                return ERR_OK;
                            } else {
                                return ERR_ABRT;
                            }
                        } else {
                            return ERR_ABRT;
                        }
                    }
                }
            } else {
                return ERR_ABRT;
            }
        } else {
            if (htons(tcphdr->wnd) < 15749.0) {
                return ERR_ABRT;
            } else {
                if (htons(tcphdr->wnd) < 64520.0) {
                    if (htons(IPH_ID(iphdr)) < 5.5) {
                        return ERR_ABRT;
                    } else {
                        if (htons(tcphdr->wnd) < 16472.0) {
                            if (TCPH_HDRLEN(tcphdr) < 42.0) {
                                return ERR_ABRT;
                            } else {
                                return ERR_OK;
                            }
                        } else {
                            if (htons(tcphdr->wnd) < 64157.0) {
                                return ERR_ABRT;
                            } else {
                                return ERR_OK;
                            }
                        }
                    }
                } else {
                    if (htons(IPH_LEN(iphdr)) < 62.0) {
                        return ERR_ABRT;
                    } else {
                        return ERR_ABRT;
                    }
                }
            }
        }
    } else {
        if ((htons(IPH_LEN(iphdr)) - htons(IPH_HL(iphdr))) < 6.5) {
            return ERR_ABRT;
        } else {
            return ERR_ABRT;
        }
    }

    return ERR_OK;
}

err_t decision_tree_depth_8(struct pbuf *p) {
    const struct ip_hdr *iphdr = (struct ip_hdr *)p->payload;

    if (IPH_PROTO(iphdr) != IP_PROTO_TCP) {
        ESP_LOGI(TAG, "IS_NOT_A_TCP_PACKET");
        return ERR_OK;
    }
    ESP_LOGI(TAG, "IS_A_TCP_PACKET");

    u16_t iphdr_hlen = IPH_HL_BYTES(iphdr);
  /* increase payload pointer (guarded by length check above) */
  struct tcp_hdr *tcphdr = (struct tcp_hdr *) ((u8_t *)p->payload + iphdr_hlen);

    if (htons(IPH_LEN(iphdr)) < 64.5) {
        if (TCPH_HDRLEN(tcphdr) < 38.0) {
            if ((IPH_OFFSET(iphdr) & IP_DF) < 0.5) {
                if ((TCPH_FLAGS(tcphdr) & TCP_SYN) < 0.5) {
                    if (htons(IPH_LEN(iphdr)) < 40.5) {
                        if (htons(tcphdr->wnd) < 506.5) {
                            return ERR_ABRT;
                        } else {
                            if (htons(tcphdr->wnd) < 1300.0) {
                                if (htons(tcphdr->wnd) < 1024.5) {
                                    return ERR_OK;
                                } else {
                                    return ERR_OK;
                                }
                            } else {
                                if ((TCPH_FLAGS(tcphdr) & TCP_FIN) < 0.5) {
                                    return ERR_ABRT;
                                } else {
                                    return ERR_ABRT;
                                }
                            }
                        }
                    } else {
                        if ((TCPH_FLAGS(tcphdr) & TCP_FIN) < 0.5) {
                            return ERR_ABRT;
                        } else {
                            return ERR_ABRT;
                        }
                    }
                } else {
                    if (htons(tcphdr->wnd) < 65524.0) {
                        if (htons(IPH_LEN(iphdr)) < 42.0) {
                            if (htons(tcphdr->wnd) < 520.5) {
                                if (htons(tcphdr->wnd) < 506.5) {
                                    return ERR_ABRT;
                                } else {
                                    return ERR_OK;
                                }
                            } else {
                                if (htons(tcphdr->wnd) < 1064.0) {
                                    return ERR_ABRT;
                                } else {
                                    return ERR_ABRT;
                                }
                            }
                        } else {
                            if (htons(tcphdr->wnd) < 1026.0) {
                                if (htons(tcphdr->wnd) < 933.0) {
                                    return ERR_ABRT;
                                } else {
                                    return ERR_OK;
                                }
                            } else {
                                return ERR_ABRT;
                            }
                        }
                    } else {
                        if (htons(IPH_TOS(iphdr) >> 2) < 4.0) {
                            if (htons(IPH_LEN(iphdr)) < 42.0) {
                                return ERR_OK;
                            } else {
                                return ERR_ABRT;
                            }
                        } else {
                            return ERR_ABRT;
                        }
                    }
                }
            } else {
                return ERR_ABRT;
            }
        } else {
            if (htons(tcphdr->wnd) < 15749.0) {
                return ERR_ABRT;
            } else {
                if (htons(tcphdr->wnd) < 64520.0) {
                    if (htons(IPH_ID(iphdr)) < 5.5) {
                        return ERR_ABRT;
                    } else {
                        if (htons(tcphdr->wnd) < 16472.0) {
                            if (TCPH_HDRLEN(tcphdr) < 42.0) {
                                return ERR_ABRT;
                            } else {
                                return ERR_OK;
                            }
                        } else {
                            if (htons(tcphdr->wnd) < 64157.0) {
                                return ERR_ABRT;
                            } else {
                                if (htons(IPH_ID(iphdr)) < 55505.5) {
                                    return ERR_OK;
                                } else {
                                    return ERR_OK;
                                }
                            }
                        }
                    }
                } else {
                    if (htons(IPH_LEN(iphdr)) < 62.0) {
                        return ERR_ABRT;
                    } else {
                        return ERR_ABRT;
                    }
                }
            }
        }
    } else {
        if (htons(tcphdr->wnd) < 2.0) {
            return ERR_ABRT;
        } else {
            return ERR_ABRT;
        }
    }

    return ERR_OK;
}

err_t decision_tree_depth_9(struct pbuf *p) {
    const struct ip_hdr *iphdr = (struct ip_hdr *)p->payload;

    if (IPH_PROTO(iphdr) != IP_PROTO_TCP) {
        ESP_LOGI(TAG, "IS_NOT_A_TCP_PACKET");
        return ERR_OK;
    }
    ESP_LOGI(TAG, "IS_A_TCP_PACKET");

    u16_t iphdr_hlen = IPH_HL_BYTES(iphdr);
    /* increase payload pointer (guarded by length check above) */
    struct tcp_hdr *tcphdr = (struct tcp_hdr *) ((u8_t *)p->payload + iphdr_hlen);

    if (htons(IPH_LEN(iphdr)) < 64.5) {
        if (TCPH_HDRLEN(tcphdr) < 38.0) {
            if ((IPH_OFFSET(iphdr) & IP_DF) < 0.5) {
                if ((TCPH_FLAGS(tcphdr) & TCP_SYN) < 0.5) {
                    if (htons(IPH_LEN(iphdr)) < 40.5) {
                        if (htons(tcphdr->wnd) < 506.5) {
                            return ERR_ABRT;
                        } else {
                            if (htons(tcphdr->wnd) < 1300.0) {
                                if (htons(tcphdr->wnd) < 1024.5) {
                                    if (htons(tcphdr->wnd) < 946.0) {
                                        return ERR_OK;
                                    } else {
                                        return ERR_OK;
                                    }
                                } else {
                                    if ((TCPH_FLAGS(tcphdr) & TCP_RST) < 0.5) {
                                        return ERR_ABRT;
                                    } else {
                                        return ERR_OK;
                                    }
                                }
                            } else {
                                if (htons(tcphdr->wnd) < 1433.0) {
                                    return ERR_ABRT;
                                } else {
                                    return ERR_ABRT;
                                }
                            }
                        }
                    } else {
                        if ((htons(IPH_LEN(iphdr)) - htons(IPH_HL(iphdr))) < 0.5) {
                            return ERR_ABRT;
                        } else {
                            return ERR_ABRT;
                        }
                    }
                } else {
                    if (htons(tcphdr->wnd) < 65524.0) {
                        if (htons(IPH_LEN(iphdr)) < 42.0) {
                            if (htons(tcphdr->wnd) < 520.5) {
                                if (htons(tcphdr->wnd) < 506.5) {
                                    return ERR_ABRT;
                                } else {
                                    return ERR_OK;
                                }
                            } else {
                                if (htons(tcphdr->wnd) < 1064.0) {
                                    if (htons(IPH_TOS(iphdr) >> 2) < 2.0) {
                                        return ERR_ABRT;
                                    } else {
                                        return ERR_ABRT;
                                    }
                                } else {
                                    return ERR_ABRT;
                                }
                            }
                        } else {
                            if (htons(tcphdr->wnd) < 1026.0) {
                                if (htons(tcphdr->wnd) < 933.0) {
                                    return ERR_ABRT;
                                } else {
                                    if (htons(IPH_TOS(iphdr) >> 2) < 4.0) {
                                        return ERR_OK;
                                    } else {
                                        return ERR_ABRT;
                                    }
                                }
                            } else {
                                return ERR_ABRT;
                            }
                        }
                    } else {
                        if (htons(IPH_TOS(iphdr) >> 2) < 4.0) {
                            if (htons(IPH_LEN(iphdr)) < 42.0) {
                                return ERR_OK;
                            } else {
                                return ERR_ABRT;
                            }
                        } else {
                            return ERR_ABRT;
                        }
                    }
                }
            } else {
                return ERR_ABRT;
            }
        } else {
            if (htons(tcphdr->wnd) < 15749.0) {
                return ERR_ABRT;
            } else {
                if (htons(tcphdr->wnd) < 64520.0) {
                    if (htons(IPH_ID(iphdr)) < 5.5) {
                        return ERR_ABRT;
                    } else {
                        if (htons(tcphdr->wnd) < 16472.0) {
                            if (htons(IPH_LEN(iphdr)) < 62.0) {
                                return ERR_ABRT;
                            } else {
                                return ERR_OK;
                            }
                        } else {
                            if (htons(tcphdr->wnd) < 64157.0) {
                                return ERR_ABRT;
                            } else {
                                if (htons(IPH_ID(iphdr)) < 55505.5) {
                                    if (htons(IPH_ID(iphdr)) < 55413.0) {
                                        return ERR_OK;
                                    } else {
                                        return ERR_ABRT;
                                    }
                                } else {
                                    return ERR_OK;
                                }
                            }
                        }
                    }
                } else {
                    if ((IPH_OFFSET(iphdr) & IP_DF) < 0.5) {
                        return ERR_ABRT;
                    } else {
                        return ERR_ABRT;
                    }
                }
            }
        }
    } else {
        if (htons(IPH_TOS(iphdr) >> 2) < 1.0) {
            return ERR_ABRT;
        } else {
            return ERR_ABRT;
        }
    }

    return ERR_OK;
}

err_t decision_tree_depth_10(struct pbuf *p) {
    const struct ip_hdr *iphdr = (struct ip_hdr *)p->payload;

    if (IPH_PROTO(iphdr) != IP_PROTO_TCP) {
        ESP_LOGI(TAG, "IS_NOT_A_TCP_PACKET");
        return ERR_OK;
    }
    ESP_LOGI(TAG, "IS_A_TCP_PACKET");

    u16_t iphdr_hlen = IPH_HL_BYTES(iphdr);
  /* increase payload pointer (guarded by length check above) */
  struct tcp_hdr *tcphdr = (struct tcp_hdr *) ((u8_t *)p->payload + iphdr_hlen);

    if (htons(IPH_LEN(iphdr)) < 64.5) {
        if (TCPH_HDRLEN(tcphdr) < 38.0) {
            if ((IPH_OFFSET(iphdr) & IP_DF) < 0.5) {
                if ((TCPH_FLAGS(tcphdr) & TCP_SYN) < 0.5) {
                    if (htons(IPH_LEN(iphdr)) < 40.5) {
                        if (htons(tcphdr->wnd) < 506.5) {
                            return ERR_ABRT;
                        } else {
                            if (htons(tcphdr->wnd) < 1300.0) {
                                if (htons(tcphdr->wnd) < 1024.5) {
                                    if (htons(tcphdr->wnd) < 946.0) {
                                        if (htons(tcphdr->wnd) < 512.5) {
                                            return ERR_OK;
                                        } else {
                                            return ERR_ABRT;
                                        }
                                    } else {
                                        return ERR_OK;
                                    }
                                } else {
                                    if ((TCPH_FLAGS(tcphdr) & TCP_ACK) < 0.5) {
                                        if (htons(IPH_TOS(iphdr) >> 2) < 4.0) {
                                            return ERR_OK;
                                        } else {
                                            return ERR_ABRT;
                                        }
                                    } else {
                                        return ERR_ABRT;
                                    }
                                }
                            } else {
                                if (htons(tcphdr->wnd) < 1433.0) {
                                    return ERR_ABRT;
                                } else {
                                    return ERR_ABRT;
                                }
                            }
                        }
                    } else {
                        if (htons(IPH_ID(iphdr)) < 6.0) {
                            return ERR_ABRT;
                        } else {
                            return ERR_ABRT;
                        }
                    }
                } else {
                    if (htons(tcphdr->wnd) < 65524.0) {
                        if (TCPH_HDRLEN(tcphdr) < 22.0) {
                            if (htons(tcphdr->wnd) < 520.5) {
                                if (htons(tcphdr->wnd) < 506.5) {
                                    return ERR_ABRT;
                                } else {
                                    return ERR_OK;
                                }
                            } else {
                                if (htons(tcphdr->wnd) < 1064.0) {
                                    if (htons(IPH_TOS(iphdr) >> 2) < 2.0) {
                                        if (htons(IPH_ID(iphdr)) < 65506.0) {
                                            return ERR_ABRT;
                                        } else {
                                            return ERR_ABRT;
                                        }
                                    } else {
                                        return ERR_ABRT;
                                    }
                                } else {
                                    return ERR_ABRT;
                                }
                            }
                        } else {
                            if (htons(tcphdr->wnd) < 1026.0) {
                                if (htons(tcphdr->wnd) < 933.0) {
                                    return ERR_ABRT;
                                } else {
                                    if (htons(IPH_TOS(iphdr) >> 2) < 4.0) {
                                        if (TCPH_HDRLEN(tcphdr) < 26.0) {
                                            return ERR_OK;
                                        } else {
                                            return ERR_ABRT;
                                        }
                                    } else {
                                        return ERR_ABRT;
                                    }
                                }
                            } else {
                                return ERR_ABRT;
                            }
                        }
                    } else {
                        if (htons(IPH_TOS(iphdr) >> 2) < 4.0) {
                            if (TCPH_HDRLEN(tcphdr) < 22.0) {
                                return ERR_OK;
                            } else {
                                return ERR_ABRT;
                            }
                        } else {
                            return ERR_ABRT;
                        }
                    }
                }
            } else {
                return ERR_ABRT;
            }
        } else {
            if (htons(tcphdr->wnd) < 15749.0) {
                return ERR_ABRT;
            } else {
                if (htons(tcphdr->wnd) < 64520.0) {
                    if (htons(IPH_ID(iphdr)) < 5.5) {
                        return ERR_ABRT;
                    } else {
                        if (htons(tcphdr->wnd) < 16472.0) {
                            if (TCPH_HDRLEN(tcphdr) < 42.0) {
                                return ERR_ABRT;
                            } else {
                                return ERR_OK;
                            }
                        } else {
                            if (htons(tcphdr->wnd) < 64157.0) {
                                return ERR_ABRT;
                            } else {
                                if (htons(IPH_ID(iphdr)) < 55505.5) {
                                    if (htons(IPH_ID(iphdr)) < 55413.0) {
                                        if (htons(IPH_ID(iphdr)) < 50709.0) {
                                            return ERR_OK;
                                        } else {
                                            return ERR_OK;
                                        }
                                    } else {
                                        return ERR_ABRT;
                                    }
                                } else {
                                    return ERR_OK;
                                }
                            }
                        }
                    }
                } else {
                    if (htons(IPH_LEN(iphdr)) < 62.0) {
                        return ERR_ABRT;
                    } else {
                        return ERR_ABRT;
                    }
                }
            }
        }
    } else {
        if ((TCPH_FLAGS(tcphdr) & TCP_SYN) < 0.5) {
            return ERR_ABRT;
        } else {
            return ERR_ABRT;
        }
    }

    return ERR_OK;
}

err_t decision_tree_depth_11(struct pbuf *p) {
    const struct ip_hdr *iphdr = (struct ip_hdr *)p->payload;

    if (IPH_PROTO(iphdr) != IP_PROTO_TCP) {
        ESP_LOGI(TAG, "IS_NOT_A_TCP_PACKET");
        return ERR_OK;
    }
    ESP_LOGI(TAG, "IS_A_TCP_PACKET");

    u16_t iphdr_hlen = IPH_HL_BYTES(iphdr);

  struct tcp_hdr *tcphdr = (struct tcp_hdr *) ((u8_t *)p->payload + iphdr_hlen);

    if (htons(IPH_LEN(iphdr)) < 64.5) {
        if (TCPH_HDRLEN(tcphdr) < 38.0) {
            if ((IPH_OFFSET(iphdr) & IP_DF) < 0.5) {
                if ((TCPH_FLAGS(tcphdr) & TCP_SYN) < 0.5) {
                    if (htons(IPH_LEN(iphdr)) < 40.5) {
                        if (htons(tcphdr->wnd) < 506.5) {
                            return ERR_ABRT;
                        } else {
                            if (htons(tcphdr->wnd) < 1300.0) {
                                if (htons(tcphdr->wnd) < 1024.5) {
                                    if (htons(tcphdr->wnd) < 946.0) {
                                        if (htons(tcphdr->wnd) < 512.5) {
                                            return ERR_OK;
                                        } else {
                                            return ERR_ABRT;
                                        }
                                    } else {
                                        return ERR_OK;
                                    }
                                } else {
                                    if ((TCPH_FLAGS(tcphdr) & TCP_RST) < 0.5) {
                                        return ERR_ABRT;
                                    } else {
                                        if (htons(IPH_TOS(iphdr) >> 2) < 4.0) {
                                            if (htons(IPH_ID(iphdr)) < 2188.5) {
                                                return ERR_OK;
                                            } else {
                                                return ERR_OK;
                                            }
                                        } else {
                                            return ERR_ABRT;
                                        }
                                    }
                                }
                            } else {
                                if ((TCPH_FLAGS(tcphdr) & TCP_PSH) < 0.5) {
                                    return ERR_ABRT;
                                } else {
                                    return ERR_ABRT;
                                }
                            }
                        }
                    } else {
                        if (htons(IPH_TOS(iphdr) >> 2) < 1.0) {
                            return ERR_ABRT;
                        } else {
                            return ERR_ABRT;
                        }
                    }
                } else {
                    if (htons(tcphdr->wnd) < 65524.0) {
                        if (htons(IPH_LEN(iphdr)) < 42.0) {
                            if (htons(tcphdr->wnd) < 520.5) {
                                if (htons(tcphdr->wnd) < 506.5) {
                                    return ERR_ABRT;
                                } else {
                                    return ERR_OK;
                                }
                            } else {
                                if (htons(tcphdr->wnd) < 1064.0) {
                                    if (htons(IPH_TOS(iphdr) >> 2) < 2.0) {
                                        if (htons(IPH_ID(iphdr)) < 65506.0) {
                                            if (htons(IPH_ID(iphdr)) < 13891.0) {
                                                return ERR_ABRT;
                                            } else {
                                                return ERR_ABRT;
                                            }
                                        } else {
                                            if (htons(IPH_ID(iphdr)) < 65509.5) {
                                                return ERR_OK;
                                            } else {
                                                return ERR_ABRT;
                                            }
                                        }
                                    } else {
                                        return ERR_ABRT;
                                    }
                                } else {
                                    return ERR_ABRT;
                                }
                            }
                        } else {
                            if (htons(tcphdr->wnd) < 1026.0) {
                                if (htons(tcphdr->wnd) < 933.0) {
                                    return ERR_ABRT;
                                } else {
                                    if (htons(IPH_TOS(iphdr) >> 2) < 4.0) {
                                        if (htons(IPH_LEN(iphdr)) < 46.0) {
                                            if (htons(IPH_ID(iphdr)) < 41126.0) {
                                                return ERR_OK;
                                            } else {
                                                return ERR_OK;
                                            }
                                        } else {
                                            return ERR_ABRT;
                                        }
                                    } else {
                                        return ERR_ABRT;
                                    }
                                }
                            } else {
                                return ERR_ABRT;
                            }
                        }
                    } else {
                        if (htons(IPH_TOS(iphdr) >> 2) < 4.0) {
                            if (TCPH_HDRLEN(tcphdr) < 22.0) {
                                return ERR_OK;
                            } else {
                                return ERR_ABRT;
                            }
                        } else {
                            return ERR_ABRT;
                        }
                    }
                }
            } else {
                return ERR_ABRT;
            }
        } else {
            if (htons(tcphdr->wnd) < 15749.0) {
                return ERR_ABRT;
            } else {
                if (htons(tcphdr->wnd) < 64520.0) {
                    if (htons(IPH_ID(iphdr)) < 5.5) {
                        return ERR_ABRT;
                    } else {
                        if (htons(tcphdr->wnd) < 16472.0) {
                            if (htons(IPH_LEN(iphdr)) < 62.0) {
                                return ERR_ABRT;
                            } else {
                                return ERR_OK;
                            }
                        } else {
                            if (htons(tcphdr->wnd) < 64157.0) {
                                return ERR_ABRT;
                            } else {
                                if (htons(IPH_ID(iphdr)) < 55505.5) {
                                    if (htons(IPH_ID(iphdr)) < 55413.0) {
                                        if (htons(IPH_ID(iphdr)) < 50709.0) {
                                            if (htons(IPH_ID(iphdr)) < 13434.5) {
                                                return ERR_OK;
                                            } else {
                                                return ERR_OK;
                                            }
                                        } else {
                                            if (htons(IPH_ID(iphdr)) < 50733.5) {
                                                return ERR_ABRT;
                                            } else {
                                                return ERR_OK;
                                            }
                                        }
                                    } else {
                                        return ERR_ABRT;
                                    }
                                } else {
                                    return ERR_OK;
                                }
                            }
                        }
                    }
                } else {
                    if (TCPH_HDRLEN(tcphdr) < 42.0) {
                        return ERR_ABRT;
                    } else {
                        return ERR_ABRT;
                    }
                }
            }
        }
    } else {
        if ((TCPH_FLAGS(tcphdr) & TCP_CWR) < 0.5) {
            return ERR_ABRT;
        } else {
            return ERR_ABRT;
        }
    }

    return ERR_OK;
}

err_t decision_tree_depth_12(struct pbuf *p) {
    const struct ip_hdr *iphdr = (struct ip_hdr *)p->payload;

    if (IPH_PROTO(iphdr) != IP_PROTO_TCP) {
        /* ESP_LOGI(TAG, "IS_NOT_A_TCP_PACKET"); */
        return ERR_OK;
    }
    /* ESP_LOGI(TAG, "IS_A_TCP_PACKET"); */

    u16_t iphdr_hlen = IPH_HL_BYTES(iphdr);
  /* increase payload pointer (guarded by length check above) */
  struct tcp_hdr *tcphdr = (struct tcp_hdr *) ((u8_t *)p->payload + iphdr_hlen);

    if (htons(IPH_LEN(iphdr)) < 64.5) {
        if (TCPH_HDRLEN(tcphdr) < 38.0) {
            if ((IPH_OFFSET(iphdr) & IP_DF) < 0.5) {
                if ((TCPH_FLAGS(tcphdr) & TCP_SYN) < 0.5) {
                    if (htons(IPH_LEN(iphdr)) < 40.5) {
                        if (htons(tcphdr->wnd) < 506.5) {
                            return ERR_OK;
                        } else {
                            if (htons(tcphdr->wnd) < 1300.0) {
                                if (htons(tcphdr->wnd) < 1024.5) {
                                    if (htons(tcphdr->wnd) < 946.0) {
                                        if (htons(tcphdr->wnd) < 512.5) {
                                            return ERR_ABRT;
                                        } else {
                                            return ERR_OK;
                                        }
                                    } else {
                                        if (htons(IPH_ID(iphdr)) < 27.0) {
                                            return ERR_ABRT;
                                        } else {
                                            return ERR_ABRT;
                                        }
                                    }
                                } else {
                                    if ((TCPH_FLAGS(tcphdr) & TCP_RST) < 0.5) {
                                        return ERR_OK;
                                    } else {
                                        if (htons(IPH_TOS(iphdr)>>2) < 4.0) {
                                            if (htons(IPH_ID(iphdr)) < 2188.5) {
                                                if (htons(IPH_ID(iphdr)) < 2017.0) {
                                                    return ERR_ABRT;
                                                } else {
                                                    return ERR_OK;
                                                }
                                            } else {
                                                if (htons(IPH_ID(iphdr)) < 13846.5) {
                                                    return ERR_ABRT;
                                                } else {
                                                    return ERR_ABRT;
                                                }
                                            }
                                        } else {
                                            return ERR_OK;
                                        }
                                    }
                                }
                            } else {
                                if (htons(IPH_ID(iphdr)) < 0.5) {
                                    return ERR_OK;
                                } else {
                                    return ERR_OK;
                                }
                            }
                        }
                    } else {
                        if ((TCPH_FLAGS(tcphdr) & TCP_PSH) < 0.5) {
                            return ERR_OK;
                        } else {
                            return ERR_OK;
                        }
                    }
                } else {
                    if (htons(tcphdr->wnd) < 65524.0) {
                        if (htons(IPH_LEN(iphdr)) < 42.0) {
                            if (htons(tcphdr->wnd) < 520.5) {
                                if (htons(tcphdr->wnd) < 506.5) {
                                    return ERR_OK;
                                } else {
                                    return ERR_ABRT;
                                }
                            } else {
                                if (htons(tcphdr->wnd) < 1064.0) {
                                    if (htons(IPH_TOS(iphdr)>>2) < 2.0) {
                                        if (htons(IPH_ID(iphdr)) < 65506.0) {
                                            if (htons(IPH_ID(iphdr)) < 13891.0) {
                                                if (htons(IPH_ID(iphdr)) < 13442.0) {
                                                    return ERR_OK;
                                                } else {
                                                    return ERR_OK;
                                                }
                                            } else {
                                                if (htons(IPH_ID(iphdr)) < 14062.0) {
                                                    return ERR_OK;
                                                } else {
                                                    return ERR_OK;
                                                }
                                            }
                                        } else {
                                            if (htons(IPH_ID(iphdr)) < 65509.5) {
                                                return ERR_ABRT;
                                            } else {
                                                if (htons(IPH_ID(iphdr)) < 65523.0) {
                                                    return ERR_OK;
                                                } else {
                                                    return ERR_ABRT;
                                                }
                                            }
                                        }
                                    } else {
                                        return ERR_OK;
                                    }
                                } else {
                                    return ERR_OK;
                                }
                            }
                        } else {
                            if (htons(tcphdr->wnd) < 1026.0) {
                                if (htons(tcphdr->wnd) < 933.0) {
                                    return ERR_OK;
                                } else {
                                    if (htons(IPH_TOS(iphdr)>>2) < 4.0) {
                                        if (htons(IPH_LEN(iphdr)) < 46.0) {
                                            if (htons(IPH_ID(iphdr)) < 41126.0) {
                                                if (htons(IPH_ID(iphdr)) < 40935.5) {
                                                    return ERR_ABRT;
                                                } else {
                                                    return ERR_OK;
                                                }
                                            } else {
                                                if (htons(IPH_ID(iphdr)) < 50774.5) {
                                                    return ERR_ABRT;
                                                } else {
                                                    return ERR_ABRT;
                                                }
                                            }
                                        } else {
                                            return ERR_OK;
                                        }
                                    } else {
                                        return ERR_OK;
                                    }
                                }
                            } else {
                                return ERR_OK;
                            }
                        }
                    } else {
                        if (htons(IPH_TOS(iphdr)>>2) < 4.0) {
                            if (htons(IPH_LEN(iphdr)) < 42.0) {
                                return ERR_ABRT;
                            } else {
                                return ERR_OK;
                            }
                        } else {
                            return ERR_OK;
                        }
                    }
                }
            } else {
                return ERR_OK;
            }
        } else {
            if (htons(tcphdr->wnd) < 15749.0) {
                return ERR_OK;
            } else {
                if (htons(tcphdr->wnd) < 64520.0) {
                    if (htons(IPH_ID(iphdr)) < 5.5) {
                        return ERR_OK;
                    } else {
                        if (htons(tcphdr->wnd) < 16472.0) {
                            if (htons(IPH_LEN(iphdr)) < 62.0) {
                                return ERR_OK;
                            } else {
                                return ERR_ABRT;
                            }
                        } else {
                            if (htons(tcphdr->wnd) < 64157.0) {
                                return ERR_OK;
                            } else {
                                if (htons(IPH_ID(iphdr)) < 55505.5) {
                                    if (htons(IPH_ID(iphdr)) < 55413.0) {
                                        if (htons(IPH_ID(iphdr)) < 50709.0) {
                                            if (htons(IPH_ID(iphdr)) < 13434.5) {
                                                if (htons(IPH_ID(iphdr)) < 13405.5) {
                                                    return ERR_ABRT;
                                                } else {
                                                    return ERR_OK;
                                                }
                                            } else {
                                                if (htons(IPH_ID(iphdr)) < 29598.5) {
                                                    return ERR_ABRT;
                                                } else {
                                                    return ERR_ABRT;
                                                }
                                            }
                                        } else {
                                            if (htons(IPH_ID(iphdr)) < 50733.5) {
                                                return ERR_OK;
                                            } else {
                                                if (htons(IPH_ID(iphdr)) < 52240.5) {
                                                    return ERR_ABRT;
                                                } else {
                                                    return ERR_ABRT;
                                                }
                                            }
                                        }
                                    } else {
                                        return ERR_OK;
                                    }
                                } else {
                                    return ERR_ABRT;
                                }
                            }
                        }
                    }
                } else {
                    if (htons(IPH_TOS(iphdr)>>2) < 4.0) {
                        return ERR_OK;
                    } else {
                        return ERR_OK;
                    }
                }
            }
        }
    } else {
        if (htons(IPH_LEN(iphdr)) < 65.5) {
            return ERR_OK;
        } else {
            return ERR_OK;
        }
    }

    return ERR_OK;
}
