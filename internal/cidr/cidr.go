// Package cidr 实现 IPv4 网段（CIDR）的解析、校验、归属判断、最小不相交聚合、
// 子网划分与网段信息计算。全部基于 uint32 表示 IPv4 地址，仅使用标准库。
//
// 关键不变量：CIDR 块按自身大小对齐（前缀 p 的块起始地址是 2^(32-p) 的整数倍），
// 因此任意两个规整后的网段只可能“相等、包含或不相交”，绝不会部分重叠。
// 聚合算法正是利用这一性质：先去除被包含的子段，再用栈合并可构成超网的相邻等长段。
package cidr

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// 解析与计算过程中可能返回的错误。调用方可通过 errors.Is 精确区分。
var (
	ErrInvalidIP        = errors.New("cidr: 非法的 IPv4 地址")
	ErrInvalidPrefix    = errors.New("cidr: 非法的 CIDR 前缀长度")
	ErrInvalidCIDR      = errors.New("cidr: 非法的 CIDR 表示")
	ErrEmptyCIDRList    = errors.New("cidr: 网段列表不能为空")
	ErrSplitCountNotPow2 = errors.New("cidr: 子网数必须是 2 的正整数次幂")
	ErrSplitPrefixOverflow = errors.New("cidr: 子网前缀超过 32")
)

// Block 一个规整后的 IPv4 网段：Network 为主机位清零后的网络地址，Prefix 为前缀长度。
type Block struct {
	Network uint32
	Prefix  int
}

// ParseIPv4 将点分十进制 IPv4 字符串解析为 uint32。
// 校验规则：恰好 4 段；每段为十进制整数且值在 0–255；禁止空段、非数字字符与前导零
// （单独的 "0" 合法，"00"、"010" 非法）。校验失败返回 ErrInvalidIP。
func ParseIPv4(s string) (uint32, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return 0, ErrInvalidIP
	}
	var ip uint32
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return 0, ErrInvalidIP
		}
		// 前导零：长度大于 1 且首位为 '0' 即非法（"0" 合法、"00"/"010" 非法）。
		if len(p) > 1 && p[0] == '0' {
			return 0, ErrInvalidIP
		}
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return 0, ErrInvalidIP
			}
		}
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 || v > 255 {
			return 0, ErrInvalidIP
		}
		ip = (ip << 8) | uint32(v)
	}
	return ip, nil
}

// FormatIPv4 将 uint32 格式化为点分十进制字符串。
func FormatIPv4(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(ip>>24)&0xFF,
		(ip>>16)&0xFF,
		ip&0xFF,
		(ip>>8)&0xFF,
	)
}

// Mask 返回前缀长度对应的掩码（高位为 1）。prefix 取值范围为 0–32。
// prefix 为 0 时掩码为 0；为 32 时掩码为 0xFFFFFFFF。
func Mask(prefix int) uint32 {
	if prefix <= 0 {
		return 0
	}
	if prefix >= 32 {
		return 0xFFFFFFFF
	}
	return ^uint32(0) << (32 - prefix)
}

// ParseCIDR 解析 "a.b.c.d/n" 形式的 CIDR 字符串，返回规整后的网段与原始 IP。
// 返回的 Block.Network 已把主机位清零；orig 为解析得到的原始 IP（未规整）。
// 校验失败返回对应错误（ErrInvalidCIDR / ErrInvalidIP / ErrInvalidPrefix）。
func ParseCIDR(s string) (block Block, orig uint32, err error) {
	i := strings.Index(s, "/")
	if i < 0 {
		return Block{}, 0, ErrInvalidCIDR
	}
	ipStr := s[:i]
	prefixStr := s[i+1:]
	// 前缀部分必须非空且全为数字，禁止负号、空格等。
	if len(prefixStr) == 0 {
		return Block{}, 0, ErrInvalidPrefix
	}
	for _, c := range prefixStr {
		if c < '0' || c > '9' {
			return Block{}, 0, ErrInvalidPrefix
		}
	}
	prefix, convErr := strconv.Atoi(prefixStr)
	if convErr != nil {
		return Block{}, 0, ErrInvalidPrefix
	}
	if prefix < 0 || prefix > 31 {
		return Block{}, 0, ErrInvalidPrefix
	}
	ip, ipErr := ParseIPv4(ipStr)
	if ipErr != nil {
		return Block{}, 0, ErrInvalidIP
	}
	return Block{Network: ip & Mask(prefix), Prefix: prefix}, ip, nil
}

// String 返回 "网络地址/前缀" 形式的字符串。
func (b Block) String() string {
	return fmt.Sprintf("%s/%d", FormatIPv4(b.Network), b.Prefix)
}

// Broadcast 返回网段的广播地址（主机位全置 1）。
func (b Block) Broadcast() uint32 {
	return b.Network | ^Mask(b.Prefix)
}

// HostCount 返回网段包含的主机数（2^(32-前缀)）。前缀为 0 时为 2^32。
func (b Block) HostCount() uint64 {
	return uint64(1) << (32 - b.Prefix)
}

// Contains 判断目标 IP 是否落在网段内（按规整网络地址与掩码比较）。
func (b Block) Contains(ip uint32) bool {
	return (ip & Mask(b.Prefix)) == b.Network
}

// ContainsBlock 判断当前网段是否完全包含另一网段 other。
// 利用对齐性质：A 包含 B 当且仅当 A.Prefix <= B.Prefix 且 B.Network 落在 A 的网络内。
func (b Block) ContainsBlock(other Block) bool {
	return b.Prefix <= other.Prefix && (other.Network&Mask(b.Prefix)) == b.Network
}

// Info 汇总单个网段的规整信息。
type Info struct {
	Network   string `json:"network"`
	Broadcast string `json:"broadcast"`
	Prefix    int    `json:"prefix"`
	HostCount uint64 `json:"host_count"`
}

// InfoOf 返回网段的规整网络地址、广播地址、前缀与主机数。
func InfoOf(b Block) Info {
	return Info{
		Network:   FormatIPv4(b.Network),
		Broadcast: FormatIPv4(b.Broadcast()),
		Prefix:    b.Prefix,
		HostCount: b.HostCount(),
	}
}

// ContainsMatch 归属判断结果：是否命中及命中的网段（最长前缀匹配）。
type ContainsMatch struct {
	Contained bool   `json:"contained"`
	Matched   string `json:"matched"`
}

// LongestContains 在网段列表中查找包含 ip 的最具体网段。
// 多个命中时取前缀最长者；前缀并列时取网络地址较小者；均不命中时 Contained 为 false、Matched 为空。
// 列表为空返回未命中；解析失败的网段条目被跳过（不影响其余条目判断）。
func LongestContains(cidrs []string, ipStr string) (ContainsMatch, error) {
	ip, err := ParseIPv4(ipStr)
	if err != nil {
		return ContainsMatch{}, err
	}
	var best *Block
	for _, c := range cidrs {
		b, _, perr := ParseCIDR(c)
		if perr != nil {
			return ContainsMatch{}, perr
		}
		if !b.Contains(ip) {
			continue
		}
		if best == nil ||
			b.Prefix > best.Prefix ||
			(b.Prefix == best.Prefix && b.Network < best.Network) {
			tmp := b
			best = &tmp
		}
	}
	if best == nil {
		return ContainsMatch{Contained: false, Matched: ""}, nil
	}
	return ContainsMatch{Contained: true, Matched: best.String()}, nil
}

// Aggregate 将一组 CIDR 聚合为最小不相交集合：丢弃被包含的子段，
// 合并可构成超网的相邻等长段。结果按网络地址升序、并列按前缀升序排列。
// 解析失败的条目导致整体返回错误；输入为空时返回空切片。
func Aggregate(cidrs []string) ([]Block, error) {
	blocks := make([]Block, 0, len(cidrs))
	seen := make(map[uint32]struct{}, len(cidrs))
	for _, c := range cidrs {
		b, _, err := ParseCIDR(c)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[b.Network]; ok {
			continue // 去重
		}
		seen[b.Network] = struct{}{}
		blocks = append(blocks, b)
	}
	if len(blocks) == 0 {
		return []Block{}, nil
	}

	// 按（网络地址升序，前缀升序）排序：容器排在被包含者之前，且相同网络地址时小前缀在前。
	sort.Slice(blocks, func(i, j int) bool {
		if blocks[i].Network != blocks[j].Network {
			return blocks[i].Network < blocks[j].Network
		}
		return blocks[i].Prefix < blocks[j].Prefix
	})

	// 第一步：去除被已保留网段包含的子段。利用对齐与排序性质，
	// 当前块若被最近保留的块包含则丢弃，否则保留。
	kept := make([]Block, 0, len(blocks))
	for _, b := range blocks {
		if len(kept) > 0 && kept[len(kept)-1].ContainsBlock(b) {
			continue
		}
		kept = append(kept, b)
	}

	// 第二步：用栈合并可构成超网的相邻等长段。
	// 两个等长（prefix=p）相邻块合并为 /p-1 的条件：低块广播地址+1 等于高块网络地址，
	// 且低块在 (32-p) 位为 0（即低块是 /p-1 超网的下半段）。
	stack := make([]Block, 0, len(kept))
	for _, b := range kept {
		cur := b
		for len(stack) > 0 {
			top := stack[len(stack)-1]
			bit := uint32(1) << (32 - top.Prefix)
			if top.Prefix == cur.Prefix &&
				top.Broadcast()+1 == cur.Network &&
				(top.Network&bit) == 0 {
				stack = stack[:len(stack)-1]
				cur = Block{Network: top.Network, Prefix: top.Prefix - 1}
			} else {
				break
			}
		}
		stack = append(stack, cur)
	}
	return stack, nil
}

// Split 将网段 b 等分为 N 个子网。N 必须为 2 的正整数次幂且 b.Prefix+log2(N) <= 32。
// 子网按网络地址升序返回，并集等于原网段且两两不相交。N=1 时返回原网段。
func Split(b Block, n int) ([]Block, error) {
	if n < 1 || (n&(n-1)) != 0 {
		return nil, ErrSplitCountNotPow2
	}
	if n == 1 {
		return nil, nil
	}
	subPrefix := b.Prefix + log2(n)
	if subPrefix > 32 {
		return nil, ErrSplitPrefixOverflow
	}
	subnets := make([]Block, n)
	size := uint64(1) << (32 - subPrefix)
	for i := 0; i < n; i++ {
		subnets[i] = Block{
			Network: b.Network + uint32(uint64(i)*size),
			Prefix:  subPrefix,
		}
	}
	return subnets, nil
}

// log2 返回 2 的幂 n 的以 2 为底对数（n 必须为正的 2 的幂）。
func log2(n int) int {
	r := 0
	for n > 1 {
		n >>= 1
		r++
	}
	return r
}
