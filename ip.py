from iputils import *
import struct


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.counter = 0

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.
        dest_addr = str2addr(dest_addr)
        dest_addr, = struct.unpack('!I', dest_addr)
        result = []
        for linha in self.tabela:
            cidr, next_hop = linha
            addr, n = cidr.split("/")

            addr = str2addr(addr)
            addr, = struct.unpack('!I', addr)
            d_addr = dest_addr >> 32-int(n) << 32-int(n)

            if addr == d_addr:
                result.append((int(n), next_hop))

        if len(result):
            resultSorted = sorted(result, reverse=True, key=lambda tup: tup[0])
            longer = resultSorted[0]
            resultNextHop = longer[1]
            return resultNextHop



    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        self.tabela = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.

        # version = 4
        # ihl = 5
        byte0 = struct.pack("!B", 0x45)

        # dscp = ecn = 0
        byte1 = struct.pack("!B", 0x00)

        totalLength = 20 + len(segmento)
        byte2and3 = struct.pack("!H", totalLength)

        identification = self.counter
        self.counter += 1
        byte4and5 = struct.pack("!H", identification)

        # flags = fragmentOffset = 0
        byte6and7 = struct.pack("!H", 0x00)

        timeToLive = 64
        byte8 = struct.pack("!B", timeToLive)

        # protocol = 6
        byte9 = struct.pack("!B", 0x06)

        # headerChecksum = 0
        byte10and11 = struct.pack("!H", 0x0000)

        sourceIpAddr, = struct.unpack('!I', str2addr(self.meu_endereco))
        byte12to15 = struct.pack("!I", sourceIpAddr)

        destIpAddr, = struct.unpack('!I', str2addr(dest_addr))
        byte16to19 = struct.pack("!I", destIpAddr)

        datagrama = byte0 + byte1 + byte2and3 + byte4and5 + byte6and7 + byte8 + byte9 + byte10and11 + byte12to15 + byte16to19
        headerChecksum = calc_checksum(datagrama)
        byte10and11 = struct.pack("!H", headerChecksum)
        datagrama = byte0 + byte1 + byte2and3 + byte4and5 + byte6and7 + byte8 + byte9 + byte10and11 + byte12to15 + byte16to19
        self.enlace.enviar(datagrama + segmento, next_hop)
