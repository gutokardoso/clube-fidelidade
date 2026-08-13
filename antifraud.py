from security import now_ts

class FraudError(Exception):
    def __init__(self, code, message, requires_manager=False):
        super().__init__(message)
        self.code = code
        self.message = message
        self.requires_manager = requires_manager


def validate_stamp(conn, membership, campaign, user, quantity=1):
    if membership['status'] != 'active':
        raise FraudError('membership_blocked', 'Cartão bloqueado. Procure um gerente.')
    if quantity < 1 or quantity > 10:
        raise FraudError('invalid_quantity', 'Quantidade inválida.')
    if quantity > 1 and user['role'] != 'manager':
        raise FraudError('manager_required', 'Crédito múltiplo exige autorização de gerente.', True)

    now = now_ts()
    last = conn.execute("SELECT created_at FROM transactions WHERE membership_id=? AND type='stamp' ORDER BY created_at DESC LIMIT 1",
                        (membership['id'],)).fetchone()
    if last and user['role'] != 'manager' and int(campaign['min_stamp_interval_sec'] or 0) > 0:
        delta = now - last['created_at']
        if delta < campaign['min_stamp_interval_sec']:
            wait = campaign['min_stamp_interval_sec'] - delta
            raise FraudError('too_fast', f'Aguarde {wait}s antes de lançar outro selo neste cartão.')

    hour_count = conn.execute("SELECT COALESCE(SUM(value),0) n FROM transactions WHERE membership_id=? AND type='stamp' AND created_at>=?",
                              (membership['id'], now-3600)).fetchone()['n']
    if int(campaign['max_stamps_per_hour'] or 0) > 0 and hour_count + quantity > campaign['max_stamps_per_hour'] and user['role'] != 'manager':
        raise FraudError('hourly_limit', 'Limite de selos por hora atingido. Gerente necessário.', True)

    day_start = now - 86400
    attendant_count = conn.execute("SELECT COALESCE(SUM(value),0) n FROM transactions WHERE user_id=? AND type='stamp' AND created_at>=?",
                                    (user['user_id'], day_start)).fetchone()['n']
    if attendant_count + quantity > campaign['max_stamps_per_attendant_day'] and user['role'] != 'manager':
        raise FraudError('attendant_daily_limit', 'Limite operacional diário do atendente atingido.', True)

    return True
