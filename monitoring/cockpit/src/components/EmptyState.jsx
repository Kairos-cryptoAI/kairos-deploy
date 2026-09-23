import { Icon } from './Icons.jsx';

export default function EmptyState({ children, compact = false }) {
  return (
    <div className={compact ? 'empty-state empty-state--compact' : 'empty-state'}>
      <Icon name="empty" size={28} />
      <p>{children}</p>
    </div>
  );
}
