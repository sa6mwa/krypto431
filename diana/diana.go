// This package is used to encode a letter according to the DIANA Cryptosystem
// developed by United States NSA. DIANA is usually called a trigraph cipher as
// it requires 3 letters for encryption/decryption similar to most
// Vigenere-based ciphers. The beauty of the DIANA cipher is the reverse
// representation of the alphabeth - reverse of A is Z, reverse of B is Y, C is
// X, etc. This makes it possible to use the exact same procedure for both
// encryption and decryption. It does also not matter if you use the
// plain-letter/key-letter as a row or column (or vice versa) - you still get
// the same result. This makes it failsafe when you are tired and under stress
// with the added bonus of being combat proven (US Special Forces during the
// Vietnam War and by US operatives during the Cold War). This made it an
// obvious choice for the Krypto431 system which this package is designed for.
//
// This is the trigraph table...
// Third letter (trigraph) = (25 - row - column) % 26
// where % is a modulo function like this: (((x % y) + y) % y)
//
// 0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25
// A  B  C  D  E  F  G  H  I  J  K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z
// -----------------------------------------------------------------------------
// Az Ay Ax Aw Av Au At As Ar Aq Ap Ao An Am Al Ak Aj Ai Ah Ag Af Ae Ad Ac Ab Aa
// By Bx Bw Bv Bu Bt Bs Br Bq Bp Bo Bn Bm Bl Bk Bj Bi Bh Bg Bf Be Bd Bc Bb Ba Bz
// Cx Cw Cv Cu Ct Cs Cr Cq Cp Co Cn Cm Cl Ck Cj Ci Ch Cg Cf Ce Cd Cc Cb Ca Cz Cy
// Dw Dv Du Dt Ds Dr Dq Dp Do Dn Dm Dl Dk Dj Di Dh Dg Df De Dd Dc Db Da Dz Dy Dx
// Ev Eu Et Es Er Eq Ep Eo En Em El Ek Ej Ei Eh Eg Ef Ee Ed Ec Eb Ea Ez Ey Ex Ew
// Fu Ft Fs Fr Fq Fp Fo Fn Fm Fl Fk Fj Fi Fh Fg Ff Fe Fd Fc Fb Fa Fz Fy Fx Fw Fv
// Gt Gs Gr Gq Gp Go Gn Gm Gl Gk Gj Gi Gh Gg Gf Ge Gd Gc Gb Ga Gz Gy Gx Gw Gv Gu
// Hs Hr Hq Hp Ho Hn Hm Hl Hk Hj Hi Hh Hg Hf He Hd Hc Hb Ha Hz Hy Hx Hw Hv Hu Ht
// Ir Iq Ip Io In Im Il Ik Ij Ii Ih Ig If Ie Id Ic Ib Ia Iz Iy Ix Iw Iv Iu It Is
// Jq Jp Jo Jn Jm Jl Jk Jj Ji Jh Jg Jf Je Jd Jc Jb Ja Jz Jy Jx Jw Jv Ju Jt Js Jr
// Kp Ko Kn Km Kl Kk Kj Ki Kh Kg Kf Ke Kd Kc Kb Ka Kz Ky Kx Kw Kv Ku Kt Ks Kr Kq
// Lo Ln Lm Ll Lk Lj Li Lh Lg Lf Le Ld Lc Lb La Lz Ly Lx Lw Lv Lu Lt Ls Lr Lq Lp
// Mn Mm Ml Mk Mj Mi Mh Mg Mf Me Md Mc Mb Ma Mz My Mx Mw Mv Mu Mt Ms Mr Mq Mp Mo
// Nm Nl Nk Nj Ni Nh Ng Nf Ne Nd Nc Nb Na Nz Ny Nx Nw Nv Nu Nt Ns Nr Nq Np No Nn
// Ol Ok Oj Oi Oh Og Of Oe Od Oc Ob Oa Oz Oy Ox Ow Ov Ou Ot Os Or Oq Op Oo On Om
// Pk Pj Pi Ph Pg Pf Pe Pd Pc Pb Pa Pz Py Px Pw Pv Pu Pt Ps Pr Pq Pp Po Pn Pm Pl
// Qj Qi Qh Qg Qf Qe Qd Qc Qb Qa Qz Qy Qx Qw Qv Qu Qt Qs Qr Qq Qp Qo Qn Qm Ql Qk
// Ri Rh Rg Rf Re Rd Rc Rb Ra Rz Ry Rx Rw Rv Ru Rt Rs Rr Rq Rp Ro Rn Rm Rl Rk Rj
// Sh Sg Sf Se Sd Sc Sb Sa Sz Sy Sx Sw Sv Su St Ss Sr Sq Sp So Sn Sm Sl Sk Sj Si
// Tg Tf Te Td Tc Tb Ta Tz Ty Tx Tw Tv Tu Tt Ts Tr Tq Tp To Tn Tm Tl Tk Tj Ti Th
// Uf Ue Ud Uc Ub Ua Uz Uy Ux Uw Uv Uu Ut Us Ur Uq Up Uo Un Um Ul Uk Uj Ui Uh Ug
// Ve Vd Vc Vb Va Vz Vy Vx Vw Vv Vu Vt Vs Vr Vq Vp Vo Vn Vm Vl Vk Vj Vi Vh Vg Vf
// Wd Wc Wb Wa Wz Wy Wx Ww Wv Wu Wt Ws Wr Wq Wp Wo Wn Wm Wl Wk Wj Wi Wh Wg Wf We
// Xc Xb Xa Xz Xy Xx Xw Xv Xu Xt Xs Xr Xq Xp Xo Xn Xm Xl Xk Xj Xi Xh Xg Xf Xe Xd
// Yb Ya Yz Yy Yx Yw Yv Yu Yt Ys Yr Yq Yp Yo Yn Ym Yl Yk Yj Yi Yh Yg Yf Ye Yd Yc
// Za Zz Zy Zx Zw Zv Zu Zt Zs Zr Zq Zp Zo Zn Zm Zl Zk Zj Zi Zh Zg Zf Ze Zd Zc Zb

package diana

import (
	"errors"
)

// TrigraphByte writes the trigraph of input X and Y (where X is usually the
// row and Y is the column, but this does not matter). Pointers are used in the
// effort to prevent anything from the input being copied. Krypto431 wipes it's
// data structures and if there would be copies elsewhere it would be in vain.
func TrigraphByte(writeTo *byte, x *byte, y *byte) error {
	if writeTo == nil || x == nil || y == nil {
		return errors.New("Trigraph: no inputs can be nil")
	}
	if (*x < byte('A') || *x > byte('Z')) || (*y < byte('A') || *y > byte('Z')) {
		return errors.New("Trigraph: input X and Y must be between A and Z")
	}
	// DIANA algorithm: 25 - x - y) & 26 = third letter, i.e trigraph With type
	// byte this will produce negative numbers and since byte is an alias for
	// uint8 (unsigned) the double modulo in order to shift sign from negative to
	// positive will fail, thus casting them as int.
	*writeTo = byte(int('A') + ((((25 - (int(*x) - int('A')) - (int(*y) - int('A'))) % 26) + 26) % 26))
	return nil
}

// TrigraphRune is the rune implementation of TrigraphByte. See TrigraphByte
// for information.
func TrigraphRune(writeTo *rune, x *rune, y *rune) error {
	if writeTo == nil || x == nil || y == nil {
		return errors.New("Trigraph: no inputs can be nil")
	}
	if (*x < 'A' || *x > 'Z') || (*y < 'A' || *y > 'Z') {
		return errors.New("Trigraph: input X and Y must be between A and Z")
	}
	// DIANA algorithm: 25 - x - y) & 26 = third letter, i.e trigraph
	// A rune is an alias for int32, signed, so that will work shifting a
	// negative number into a positive.
	*writeTo = rune('A') + ((((25 - (*x - rune('A')) - (*y - rune('A'))) % 26) + 26) % 26)
	return nil
}

// ZeroKeyByte returns a "zero" encryption letter (byte) key in order to
// trigraph-encode an input letter to the same output letter (which makes the
// plaintext same as the ciphertext, effectively a zero key in a standard
// Vigenere cipher).
func ZeroKeyByte(writeTo *byte, character *byte) error {
	return TrigraphByte(writeTo, character, character)
}

// ZeroKeyRune returns a "zero" encryption letter (rune) key in order to
// trigraph-encode an input letter to the same output letter (which makes the
// plaintext same as the ciphertext, effectively a zero key in a standard
// Vigenere cipher).
func ZeroKeyRune(writeTo *rune, character *rune) error {
	return TrigraphRune(writeTo, character, character)
}

// AppendTrigraphByteByKey will append the encoded character to a byte slice
// tracking an indexed key. It will also increment the index through the
// keyIndex pointer when done making it possible to call this function
// repeatedly per input character. You will have to check that the index is not
// out of range, function will fail if index is greater than the length of the
// byte slice. You should also ensure the the byte slice (pointing at by
// writeTo) has the desired capacity in order to prevent the append function to
// make a new slice and copy everything from the old slice, thus leaving traces
// of encrypted text in memory that you are unable to wipe by yourself.
func AppendTrigraphByteByKey(writeTo *[]byte, character *byte, key *[]byte, keyIndex *int) error {
	if writeTo == nil {
		return errors.New("output pointer can not be nil")
	}
	if key == nil {
		return errors.New("key can not be nil")
	}
	if keyIndex == nil {
		return errors.New("key index can not be nil")
	}
	if character == nil {
		return errors.New("character pointer is nil")
	}
	if *keyIndex < 0 {
		return errors.New("key index can not be negative")
	}
	if *keyIndex > len(*writeTo) {
		return errors.New("key index is out-of-bounds")
	}
	var b byte
	err := TrigraphByte(&b, character, &(*key)[*keyIndex])
	if err != nil {
		b = 0
		return err
	}
	*writeTo = append(*writeTo, b)
	b = 0
	*keyIndex++
	return nil
}
