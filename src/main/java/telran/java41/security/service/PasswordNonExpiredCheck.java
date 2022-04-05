package telran.java41.security.service;

import java.time.LocalDate;

import telran.java41.accounting.model.UserAccount;

public class PasswordNonExpiredCheck {

	public static boolean check(UserAccount userAccount) {
		return userAccount.getPwExpirationDate().isAfter(LocalDate.now().minusYears(1));
	}

}
